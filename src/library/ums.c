#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "../kernel/ums_interface.h"
#include "ums.h"

typedef struct {
	scheduler_entrypoint_t scheduler_entrypoint;
	ums_completion_list_t *ums_completion_list;
} entrypoint_key_t;

pthread_key_t entrypoint_key;
pthread_once_t entrypoint_key_once = PTHREAD_ONCE_INIT;

int ums_syscall(unsigned int req_num, void *data)
{
	int fd = open("/dev/" DEVICE_NAME, 0);
	if (fd == -1) {
		return -1;
	}

	int ret = ioctl(fd, req_num, data);

	close(fd);

	return ret;
}

int register_worker_thread()
{
	return ums_syscall(REGISTER_WORKER_THREAD, NULL);
}

int worker_thread_terminated()
{
	return ums_syscall(WORKER_THREAD_TERMINATED, NULL);
}

void create_entrypoint_key()
{
	while (pthread_key_create(&entrypoint_key, NULL) == EAGAIN) {
	}
}

int enter_ums_scheduling_mode(scheduler_entrypoint_t scheduler_entrypoint,
			      ums_completion_list_t *ums_completion_list)
{
	int ret;

	pthread_once(&entrypoint_key_once, create_entrypoint_key);

	entrypoint_key_t key;

	key.scheduler_entrypoint = scheduler_entrypoint;
	key.ums_completion_list = ums_completion_list;

	ret = pthread_setspecific(entrypoint_key, &key);
	if (ret != 0)
		return -1;

	scheduler_entrypoint(ums_completion_list);

	return 0;
}

ums_completion_list_t *create_ums_completion_list()
{
	ums_completion_list_t *ums_completion_list =
		(ums_completion_list_t *)malloc(sizeof(ums_completion_list_t));

	if (ums_completion_list == NULL)
		return NULL;

	int ret = sem_init(&ums_completion_list->avaliable_sem, 0, 0);
	if (ret == -1) {
		free(ums_completion_list);
		return NULL;
	}

	ums_completion_list->head = NULL;
	ums_completion_list->tail = NULL;
	ums_completion_list->size = 0;

	return ums_completion_list;
}

void delete_ums_completion_list(ums_completion_list_t *ums_completion_list)
{
	while (ums_completion_list->head != NULL) {
		ums_list_node_t *to_be_deleted = ums_completion_list->head;
		ums_completion_list->head = to_be_deleted->next;
		free(to_be_deleted);
	}

	sem_destroy(&ums_completion_list->avaliable_sem);
	free(ums_completion_list);
}

int enqueue_ums_completion_list(ums_completion_list_t *ums_completion_list,
				pid_t thread)
{
	ums_list_node_t *new_node =
		(ums_list_node_t *)malloc(sizeof(ums_list_node_t));
	if (new_node == NULL)
		return -1;

	new_node->thread = thread;
	new_node->next = NULL;

	if (ums_completion_list->size == 0) {
		ums_completion_list->head = new_node;
		ums_completion_list->tail = new_node;
		sem_post(&ums_completion_list->avaliable_sem);
	} else {
		ums_completion_list->tail->next = new_node;
		ums_completion_list->tail = new_node;
	}
	ums_completion_list->size++;

	return 0;
}

int execute_ums_thread(pid_t thread)
{
	int ret = ums_syscall(EXECUTE_UMS_THREAD, &thread);

	if (ret == -1) {
		/* error, thread not executed */
		return -1;
	} else if (ret == WORKER_YIELDED) {
		entrypoint_key_t *key =
			(entrypoint_key_t *)pthread_getspecific(entrypoint_key);
		if (key == NULL) {
			return -1;
		}

		enqueue_ums_completion_list(key->ums_completion_list, thread);
		key->scheduler_entrypoint(key->ums_completion_list);
	}

	return 0;
}

ums_list_node_t *
dequeue_ums_completion_list(ums_completion_list_t *ums_completion_list)
{
	while (sem_wait(&ums_completion_list->avaliable_sem)) {
		if (errno != EINTR) {
			return NULL;
		}
	}
	ums_list_node_t *ums_thread_list = ums_completion_list->head;

	ums_completion_list->head = NULL;
	ums_completion_list->tail = NULL;
	ums_completion_list->size = 0;

	return ums_thread_list;
}

ums_list_node_t *get_next_ums_list_item(ums_list_node_t *ums_thread)
{
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
	ready_queue_t *ready_queue =
		(ready_queue_t *)malloc(sizeof(ready_queue_t));

	if (ready_queue == NULL)
		return NULL;

	ready_queue->head = NULL;
	ready_queue->tail = NULL;
	ready_queue->size = 0;

	return ready_queue;
}

void delete_ready_queue(ready_queue_t *ready_queue)
{
	while (ready_queue->head != NULL) {
		ums_list_node_t *to_be_deleted = ready_queue->head;
		ready_queue->head = to_be_deleted->next;
		free(to_be_deleted);
	}

	free(ready_queue);
}

int enqueue_ready_queue(ready_queue_t *ready_queue, pid_t thread)
{
	ums_list_node_t *new_node =
		(ums_list_node_t *)malloc(sizeof(ums_list_node_t));
	if (new_node == NULL)
		return -1;

	new_node->thread = thread;
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
	if (ready_queue->size == 0)
		return -1;

	pid_t thread = ready_queue->head->thread;
	ums_list_node_t *next = ready_queue->head->next;
	free(ready_queue->head);
	ready_queue->head = next;
	ready_queue->size--;

	return thread;
}