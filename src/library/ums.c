#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "../kernel/ums_interface.h"
#include "ums.h"

/* Struct used to pass arguments to a worker thread */
struct worker_args {
	/* The routine the worker should execute */
	void	*(*start_routine)(void *);
	/* The argument for start_routine */
	void	*arg;
	/* The struct representing the worker thread */			
	ums_t	*thread;
};

pthread_key_t exit_key;
pthread_once_t exit_key_once = PTHREAD_ONCE_INIT;

pthread_key_t entrypoint_key;
pthread_once_t entrypoint_key_once = PTHREAD_ONCE_INIT;

/* File descriptor of the UMS module */
int fd = -1;

void close_at_exit() {
	close(fd);
}

/**
 * Executes a request to the UMS module.
 * If it is not already opened, it opens the file descriptor of the module
 * and registers a function to close the it whe the program exits.
 * If it cannot open the descriptor it setts errno to ENOSYS to indicate that
 * the UMS module is not loaded.
 */
int ums_syscall(unsigned int req_num, void *data)
{
	if (fd < 0) {
		fd = open("/dev/" DEVICE_NAME, 0);

		if (fd < 0) {
			errno = ENOSYS;
			return -1;
		}
		atexit(close_at_exit);
	}

	int ret = ioctl(fd, req_num, data);

	/**
	 * If errno == EBADF it means that the file descriptor was already
	 * opened in the past, but the module is not loaded anymore so it sets
	 * errno to ENOSYS 
	 */
	if (ret < 0 && errno == EBADF)
		errno = ENOSYS;

	return ret;
}

void worker_thread_destructor(void *ptr)
{
	struct worker_args *args = (struct worker_args *)ptr;

	if (args->thread->pid > 0) {
		ums_syscall(WORKER_THREAD_TERMINATED, 0);
		free(args);
	}
}

void create_exit_key()
{
	while (pthread_key_create(&exit_key, worker_thread_destructor) ==
	       EAGAIN)
		continue;
}

void *worker_thread_start_routine(void *ptr)
{
	int ret;
	struct worker_args *args = (struct worker_args *)ptr;

	/**
	 * We set exit_key to args. This is a trick to make it so that the key
	 * destructor worker_thread_destructor is executed when the worker
	 * terminates. worker_thread_destructor will execute the
	 * WORKER_THREAD_TERMINATED syscall to notify the ums module of the
	 * worker termination
	 */
	pthread_once(&exit_key_once, create_exit_key);
	ret = pthread_setspecific(exit_key, args);
	if (ret != 0) {
		args->thread->pid = -ENOMEM;
		return NULL;
	}

	/**
	 * Registering the worker thread. If successful the thread wiil be
	 * blocked until it is scheduler by a ums scheduler. The syscall will
	 * also put the worker pid in args->thread->pid, notifing the parent
	 * thread of the succesful creation of the worker
	 */
	ret = ums_syscall(REGISTER_WORKER_THREAD, &args->thread->pid);
	if (ret < 0) {
		args->thread->pid = -errno;
		return NULL;
	}

	/* Executing the thread start_routine passed by the user */
	return args->start_routine(args->arg);
}

int create_ums_thread(ums_t *thread, void *(*start_routine)(void *), void *arg)
{
	struct worker_args *args =
		(struct worker_args *)malloc(sizeof(struct worker_args));
	if (args == NULL)
		return -1;

	args->start_routine = start_routine;
	args->arg = arg;
	args->thread = thread;
	thread->pid = 0;

	/* Creating the worker thread */
	int ret = pthread_create(&thread->pthread_id, NULL,
				 worker_thread_start_routine, (void *)args);
	if (ret != 0) {
		free(args);
		errno = ret;
		return -1;
	}

	/**
	 * Waiting for the worker thread to set thread->pid to its pid,
	 * signaling a successful creation
	 */
	while (thread->pid == 0)
		continue;

	/**
	 * If thread->pid is less then zero it means that the worker thread
	 * encoutered an error during initialization and set thread->pid to the
	 * error code negated. We then join the thread and return the error to
	 * the caller
	 */
	if (thread->pid < 0) {
		free(args);
		pthread_join(thread->pthread_id, NULL);
		errno = -thread->pid;
		return -1;
	}

	return 0;
}

void create_entrypoint_key()
{
	while (pthread_key_create(&entrypoint_key, NULL) == EAGAIN)
		continue;
}

int enter_ums_scheduling_mode(scheduler_entrypoint_t entrypoint,
			      ums_completion_list_t *completion_list)
{
	int ret;

	if (entrypoint == NULL || completion_list == NULL ||
	    completion_list->size == 0) {
		errno = EINVAL;
		return -1;
	}

	/* Storing the entry point function pointer in the entrypoint_key key */
	pthread_once(&entrypoint_key_once, create_entrypoint_key);
	ret = pthread_setspecific(entrypoint_key, entrypoint);
	if (ret != 0) {
		errno = ENOMEM;
		return -1;
	}

	/**
	 * Filling a thread_list struct with the pids of the workers in the
	 * completion list in order to pass the list to the ums module
	 */
	pid_t workers[completion_list->size];

	struct thread_list list;
	list.size = 0;
	list.threads = workers;

	ums_list_node_t *ptr = completion_list->head;

	while (ptr != NULL) {
		workers[list.size] = ptr->thread;
		list.size++;
		ptr = ptr->next;
	}

	/* Registering the scheduler */
	ret = ums_syscall(REGISTER_SCHEDULER_THREAD, &list);
	if (ret < 0)
		return -1;

	/*
	 * Executing the entry point function to select the first worker to
	 * schedule. The call is actually recursive: every call to
	 * execute_ums_thread inside the entry point function will result in
	 * another call to the entry point when the worker ends or yields. If
	 * the entry point has been correctly defined by the user and there are
	 * no errors, when this first call to the entry point ends all workers
	 * in the completion list should have terminated
	 */
	entrypoint();

	return 0;
}

ums_completion_list_t *create_ums_completion_list()
{
	ums_completion_list_t *ums_completion_list =
		(ums_completion_list_t *)malloc(sizeof(ums_completion_list_t));
	if (ums_completion_list == NULL)
		return NULL;

	ums_completion_list->head = NULL;
	ums_completion_list->tail = NULL;
	ums_completion_list->size = 0;

	return ums_completion_list;
}

void delete_ums_completion_list(ums_completion_list_t *completion_list)
{
	if (completion_list != NULL) {
		while (completion_list->head != NULL) {
			ums_list_node_t *to_be_deleted = completion_list->head;
			completion_list->head = to_be_deleted->next;
			free(to_be_deleted);
		}

		free(completion_list);
	}
}

int enqueue_ums_completion_list_item(ums_completion_list_t *completion_list,
				     ums_t thread)
{
	if (completion_list == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (thread.pid < 0) {
		errno = ESRCH;
		return -1;
	}

	ums_list_node_t *new_node =
		(ums_list_node_t *)malloc(sizeof(ums_list_node_t));
	if (new_node == NULL)
		return -1;

	new_node->thread = thread.pid;
	new_node->next = NULL;

	if (completion_list->size == 0) {
		completion_list->head = new_node;
		completion_list->tail = new_node;
	} else {
		completion_list->tail->next = new_node;
		completion_list->tail = new_node;
	}
	completion_list->size++;

	return 0;
}

int execute_ums_thread(pid_t thread)
{
	if (thread < 0) {
		errno = ESRCH;
		return -1;
	}

	int ret = ums_syscall(EXECUTE_UMS_THREAD, &thread);
	if (ret < 0) {
		/* Error, thread not executed. */
		return -1;
	}

	/**
	 * Retrieving the entry point function for the scheduler from the
	 * entrypoint_key key. If the execution of the worker was successful it
	 * means that execute_ums_thread was called by a registered scheduler
	 * and thus entrypoint_key must be set to the pointer of the entry point
	 * function
	 */
	scheduler_entrypoint_t scheduler_entrypoint =
		(scheduler_entrypoint_t)pthread_getspecific(entrypoint_key);

	/**
	 * Calling the entry point function to select the next worker to be
	 * scheduled
	 */
	scheduler_entrypoint();

	return 0;
}

int dequeue_ums_completion_list_items(ums_list_node_t **list)
{
	if (list == NULL) {
		errno = EINVAL;
		return -1;
	}

	int size = ums_syscall(DEQUEUE_UMS_COMPLETION_LIST_ITEMS, NULL);
	if (size < 0)
		return -1;

	/* All workers terminated */
	if (size == 0)
		return 0;

	pid_t *dequeued_list = (pid_t *)calloc(size, sizeof(pid_t));
	if (dequeued_list == NULL)
		return -1;

	int ret = ums_syscall(GET_DEQUEUED_ITEMS, dequeued_list);
	if (ret < 0) {
		ret = errno;
		free(dequeued_list);
		errno = ret;
		return -1;
	}

	ums_list_node_t *tail = NULL;
	int i;
	int err = 0;
	*list = NULL;

	for (i = 0; i < size; i++) {
		ums_list_node_t *new_node =
			(ums_list_node_t *)malloc(sizeof(ums_list_node_t));
		if (new_node == NULL) {
			err = 1;
			break;
		}

		new_node->thread = dequeued_list[i];
		new_node->next = NULL;

		if (*list == NULL) {
			*list = new_node;
			tail = new_node;
		} else {
			tail->next = new_node;
			tail = new_node;
		}
	}

	free(dequeued_list);

	if (err) {
		/* Freeing already allocated memory if one allocation failed */
		while (*list != NULL) {
			ums_list_node_t *node = (*list)->next;
			free(*list);
			*list = node;
		}
		errno = ENOMEM;
		return -1;
	}

	/* Returning the number of thread dequeued */
	return i;
}

ums_list_node_t *get_next_ums_list_item(ums_list_node_t *item)
{
	if (item == NULL)
		return NULL;

	ums_list_node_t *next = item->next;
	free(item);
	return next;
}

int ums_thread_yield()
{
	return ums_syscall(UMS_THREAD_YIELD, NULL);
}

ready_queue_t *create_ready_queue()
{
	ready_queue_t *ready_queue =
		(ready_queue_t *)malloc(sizeof(ready_queue_t));
	if (ready_queue == NULL)
		return NULL;

	ready_queue->head = NULL;
	ready_queue->tail = NULL;
	ready_queue->size = 0;

	return ready_queue;
}

int delete_ready_queue(ready_queue_t *ready_queue)
{
	if (ready_queue == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (ready_queue->size > 0) {
		errno = ENOTEMPTY;
		return -1;
	}

	free(ready_queue);
}

int enqueue_ready_queue(ready_queue_t *ready_queue, ums_list_node_t *item)
{
	if (ready_queue == NULL || item == NULL) {
		errno = EINVAL;
		return -1;
	}

	ums_list_node_t *new_node =
		(ums_list_node_t *)malloc(sizeof(ums_list_node_t));
	if (new_node == NULL)
		return -1;

	new_node->thread = item->thread;
	new_node->next = NULL;

	if (ready_queue->size == 0) {
		ready_queue->head = new_node;
		ready_queue->tail = new_node;
	} else {
		ready_queue->tail->next = new_node;
		ready_queue->tail = new_node;
	}
	ready_queue->size++;

	return 0;
}

pid_t dequeue_ready_queue(ready_queue_t *ready_queue)
{
	if (ready_queue == NULL || ready_queue->size == 0) {
		errno = EINVAL;
		return -1;
	}

	pid_t thread = ready_queue->head->thread;
	ums_list_node_t *next = ready_queue->head->next;
	free(ready_queue->head);
	ready_queue->head = next;
	ready_queue->size--;

	return thread;
}