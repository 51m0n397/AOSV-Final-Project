#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>

#include "../kernel/ums_interface.h"
#include "ums.h"

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

int worker_wait_for_scheduler()
{
	return ums_syscall(WORKER_WAIT_FOR_SCHEDULER, NULL);
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

	ret = pthread_setspecific(entrypoint_key, scheduler_entrypoint);
	if (ret != 0)
		return -1;

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
	if (ret < 0)
		return ret;

	scheduler_entrypoint();

	ret = ums_syscall(SCHEDULER_THREAD_TERMINATED, NULL);
	if (ret < 0)
		return ret;

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
	while (ums_completion_list->head != NULL) {
		ums_list_node_t *to_be_deleted = ums_completion_list->head;
		ums_completion_list->head = to_be_deleted->next;
		free(to_be_deleted);
	}

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

	if (ret < 0) {
		/* error, thread not executed */
		return -1;
	}

	scheduler_entrypoint_t scheduler_entrypoint =
		(scheduler_entrypoint_t)pthread_getspecific(entrypoint_key);
	if (scheduler_entrypoint == NULL) {
		return -1;
	}

	scheduler_entrypoint();

	return 0;
}

int dequeue_ums_completion_list(ums_list_node_t **list)
{
	int size = ums_syscall(DEQUEUE_UMS_COMPLETION_LIST_ITEMS, NULL);
	if (size < 0)
		return -1;

	if (size == 0) {
		return 0;
	}

	pid_t *dequeued_list = malloc(sizeof(pid_t) * size);

	int ret = ums_syscall(GET_DEQUEUED_ITEMS, dequeued_list);
	if (ret < 0) {
		free(dequeued_list);
		return -1;
	}

	ums_list_node_t *tail = NULL;
	for (int i = 0; i < size; i++) {
		ums_list_node_t *new_node =
			(ums_list_node_t *)malloc(sizeof(ums_list_node_t));

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

	return 1;
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
	ready_queue_t *ready_queue = (ready_queue_t *)malloc(sizeof(ready_queue_t));

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