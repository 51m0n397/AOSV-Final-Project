#ifndef UMS
#define UMS

#include <sys/types.h>

typedef struct {
	pthread_t pthread_id;
	pid_t pid;
} ums_t;

typedef struct ums_list_node {
	pid_t thread;
	struct ums_list_node *next;
} ums_list_node_t;

struct ums_list {
	ums_list_node_t *head;
	ums_list_node_t *tail;
	int size;
};

typedef struct ums_list ums_completion_list_t;
typedef struct ums_list ready_queue_t;

typedef void (*scheduler_entrypoint_t)();

int create_ums_thread(ums_t *thread, void *(*start_routine)(void *),
														 void *arg);

int enter_ums_scheduling_mode(scheduler_entrypoint_t scheduler_entrypoint,
															ums_completion_list_t *ums_completion_list);

ums_completion_list_t *create_ums_completion_list();

void delete_ums_completion_list(ums_completion_list_t *ums_completion_list);

int enqueue_ums_completion_list_item(ums_completion_list_t *ums_completion_list,
																		 ums_t thread);

int execute_ums_thread(pid_t thread);

int dequeue_ums_completion_list_items(ums_list_node_t **list);

ums_list_node_t *get_next_ums_list_item(ums_list_node_t *ums_thread);

int ums_thread_yield();

ready_queue_t *create_ready_queue();

int delete_ready_queue(ready_queue_t *ready_queue);

int enqueue_ready_queue(ready_queue_t *ready_queue, ums_list_node_t *thread);

pid_t dequeue_ready_queue(ready_queue_t *ready_queue);

#endif