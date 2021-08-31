#ifndef UMS
#define UMS

#include <sys/types.h>

typedef struct ums_completion_list_node {
	pid_t thread;
	struct ums_completion_list_node *next;
} ums_completion_list_node_t;

typedef struct {
	ums_completion_list_node_t *head;
	ums_completion_list_node_t *tail;
	int size;
} ums_completion_list_t;

typedef void (*scheduler_entrypoint_t)(
	ums_completion_list_t *ums_completion_list);

int register_worker_thread();

int worker_thread_terminated();

void enter_ums_scheduling_mode(scheduler_entrypoint_t scheduler_entrypoint,
			       ums_completion_list_t *ums_completion_list);

ums_completion_list_t *create_ums_completion_list();

void delete_ums_completion_list(ums_completion_list_t *ums_completion_list);

int enqueue_ums_completion_list(ums_completion_list_t *ums_completion_list,
				pid_t thread);

int execute_ums_thread(pid_t thread);

#endif