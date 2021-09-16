#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <semaphore.h>

#include "../kernel/ums_interface.h"
#include "ums.h"

struct worker_args {
	void *(*start_routine)(void *);
	void *arg;
	ums_t *thread;
};

pthread_key_t exit_key;
pthread_once_t exit_key_once = PTHREAD_ONCE_INIT;

pthread_key_t entrypoint_key;
pthread_once_t entrypoint_key_once = PTHREAD_ONCE_INIT;

int ums_syscall(unsigned int req_num, void *data)
{
	int fd = open("/dev/" DEVICE_NAME, 0);
	if (fd < 0) {
		/* The module is not loaded */
		errno = ENOSYS;
		return -1;
	}

	int ret = ioctl(fd, req_num, data);
	int err = errno;
	close(fd);
	errno = err;

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
	while (pthread_key_create(&exit_key, worker_thread_destructor) == EAGAIN)
		continue;
}

void *worker_thread_start_routine(void *ptr)
{
	int ret;
	struct worker_args *args = (struct worker_args *)ptr;

	pthread_once(&exit_key_once, create_exit_key);

	ret = pthread_setspecific(exit_key, args);
	if (ret != 0) {
		args->thread->pid = -ENOMEM;
		return NULL;
	}

	ret = ums_syscall(REGISTER_WORKER_THREAD, &args->thread->pid);
	if (ret < 0) {
		/* ENOSYS if the module is not loaded or errors from the module */
		args->thread->pid = -errno;
		return NULL;
	}

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

	int ret = pthread_create(&thread->pthread_id, NULL,
													 worker_thread_start_routine, (void *)args);
	if (ret != 0) {
		free(args);
		errno = ret;
		return -1;
	}

	while (thread->pid == 0)
		continue;

	if (thread->pid < 0) {
		/* ENOSYS if the module is not loaded or errors from the module */
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

int enter_ums_scheduling_mode(scheduler_entrypoint_t scheduler_entrypoint,
															ums_completion_list_t *ums_completion_list)
{
	int ret;

	if (scheduler_entrypoint == NULL || ums_completion_list == NULL ||
			ums_completion_list->size == 0) {
		errno = EINVAL;
		return -1;
	}

	pthread_once(&entrypoint_key_once, create_entrypoint_key);

	ret = pthread_setspecific(entrypoint_key, scheduler_entrypoint);
	if (ret != 0) {
		errno = ENOMEM;
		return -1;
	}

	pid_t workers[ums_completion_list->size];

	struct thread_list list;
	list.size = 0;
	list.threads = workers;

	ums_list_node_t *ptr = ums_completion_list->head;

	while (ptr != NULL) {
		workers[list.size] = ptr->thread;
		list.size++;
		ptr = ptr->next;
	}

	ret = ums_syscall(REGISTER_SCHEDULER_THREAD, &list);
	if (ret < 0) {
		/* ENOSYS if the module is not loaded or errors from the module */
		return -1;
	}

	scheduler_entrypoint();

	/* Does only cleanup. Not returning errors to caller because even if it
	 * fails the call to "enter_ums_scheduling_mode" was successfull */
	ums_syscall(SCHEDULER_THREAD_TERMINATED, NULL);

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

void delete_ums_completion_list(ums_completion_list_t *ums_completion_list)
{
	if (ums_completion_list != NULL) {
		while (ums_completion_list->head != NULL) {
			ums_list_node_t *to_be_deleted = ums_completion_list->head;
			ums_completion_list->head = to_be_deleted->next;
			free(to_be_deleted);
		}

		free(ums_completion_list);
	}
}

int enqueue_ums_completion_list_item(ums_completion_list_t *ums_completion_list,
																		 ums_t thread)
{
	if (ums_completion_list == NULL) {
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

	if (ums_completion_list->size == 0) {
		ums_completion_list->head = new_node;
		ums_completion_list->tail = new_node;
	} else {
		ums_completion_list->tail->next = new_node;
		ums_completion_list->tail = new_node;
	}
	ums_completion_list->size++;

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

	/* Not checking errors because it should not fail */
	scheduler_entrypoint_t scheduler_entrypoint =
		(scheduler_entrypoint_t)pthread_getspecific(entrypoint_key);

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
	if (size < 0) {
		/* ENOSYS if the module is not loaded or errors from the module */
		return -1;
	}

	if (size == 0) {
		/* All workers terminated */
		return 0;
	}

	pid_t *dequeued_list = (pid_t *)malloc(sizeof(pid_t) * size);
	if (dequeued_list == NULL)
		return -1;

	int ret = ums_syscall(GET_DEQUEUED_ITEMS, dequeued_list);
	if (ret < 0) {
		/* ENOSYS if the module is not loaded or errors from the module */
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

ums_list_node_t *get_next_ums_list_item(ums_list_node_t *ums_thread)
{
	if (ums_thread == NULL)
		return NULL;

	ums_list_node_t *next = ums_thread->next;
	free(ums_thread);
	return next;
}

int ums_thread_yield()
{
	return ums_syscall(UMS_THREAD_YIELD, NULL);
}

ready_queue_t *create_ready_queue()
{
	ready_queue_t *ready_queue = (ready_queue_t *)malloc(sizeof(ready_queue_t));
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

int enqueue_ready_queue(ready_queue_t *ready_queue, ums_list_node_t *thread)
{
	if (ready_queue == NULL || thread == NULL) {
		errno = EINVAL;
		return -1;
	}

	ums_list_node_t *new_node =
		(ums_list_node_t *)malloc(sizeof(ums_list_node_t));
	if (new_node == NULL)
		return -1;

	new_node->thread = thread->thread;
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