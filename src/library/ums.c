#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

#include "../kernel/ums_interface.h"
#include "ums.h"

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

void enter_ums_scheduling_mode(scheduler_entrypoint_t scheduler_entrypoint,
			       ums_completion_list_t *ums_completion_list)
{
	scheduler_entrypoint(ums_completion_list);
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
		ums_completion_list_node_t *to_be_deleted =
			ums_completion_list->head;
		ums_completion_list->head = to_be_deleted->next;
		free(to_be_deleted);
	}

	free(ums_completion_list);
}

int enqueue_ums_completion_list(ums_completion_list_t *ums_completion_list,
				pid_t thread)
{
	ums_completion_list_node_t *new_node =
		(ums_completion_list_node_t *)malloc(
			sizeof(ums_completion_list_node_t));
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
	return ums_syscall(EXECUTE_UMS_THREAD, &thread);
}