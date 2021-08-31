#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../library/ums.h"

#define NUM_WORKER_THREADS 2

void scheduler_entrypoint(ums_completion_list_t *ums_completion_list)
{
	ums_completion_list_node_t *node = ums_completion_list->head;
	while (node != NULL) {
		execute_ums_thread(node->thread);
		node = node->next;
	}
}

void *scheduler_thread_routine(void *ptr)
{
	ums_completion_list_t *completion_list = (ums_completion_list_t *)ptr;

	enter_ums_scheduling_mode(*scheduler_entrypoint, completion_list);
}

void *worker_thread_routine(void *ptr)
{
	pid_t pid = syscall(__NR_gettid);
	pid_t *pid_ptr = (pid_t *)ptr;
	*pid_ptr = pid;

	printf("Worker %d: start\n", pid);
	register_worker_thread();

	printf("Worker %d: end\n", pid);
	worker_thread_terminated();
}

int main(int argc, char *argv[])
{
	ums_completion_list_t *list = create_ums_completion_list();

	pthread_t worker_threads[NUM_WORKER_THREADS];

	for (int i = 0; i < NUM_WORKER_THREADS; i++) {
		pid_t pid = -1;

		pthread_create(&worker_threads[i], NULL, worker_thread_routine,
			       &pid);

		while (pid == -1) {
		};

		enqueue_ums_completion_list(list, pid);
	}

	pthread_t scheduler_thread;
	pthread_create(&scheduler_thread, NULL, scheduler_thread_routine,
		       (void *)list);

	for (int i = 0; i < NUM_WORKER_THREADS; i++) {
		pthread_join(worker_threads[i], NULL);
	}

	pthread_join(scheduler_thread, NULL);

	delete_ums_completion_list(list);

	return EXIT_SUCCESS;
}