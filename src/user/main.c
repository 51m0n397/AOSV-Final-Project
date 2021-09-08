#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#include "../library/ums.h"

#define NUM_WORKER_THREADS 6
#define NUM_SCHEDULER_THREADS 3

pthread_key_t ready_queue_key;

void scheduler_entrypoint()
{
	ready_queue_t *ready_queue =
		(ready_queue_t *)pthread_getspecific(ready_queue_key);

	pid_t pid = syscall(__NR_gettid);

	if (ready_queue->size == 0) {
		ums_list_node_t *available_thread = NULL;

		dequeue_ums_completion_list(&available_thread);

		while (available_thread != NULL) {
			enqueue_ready_queue(ready_queue, available_thread->thread);
			available_thread = get_next_ums_list_item(available_thread);
		}
	}

	while (ready_queue->size > 0) {
		pid_t thread = dequeue_ready_queue(ready_queue);
		printf("Scheduler: executing thread %d\n", thread);
		execute_ums_thread(thread);
	}
}

void *scheduler_thread_routine(void *ptr)
{
	ums_completion_list_t *completion_list = (ums_completion_list_t *)ptr;

	ready_queue_t *ready_queue = create_ready_queue();
	pthread_setspecific(ready_queue_key, ready_queue);

	enter_ums_scheduling_mode(*scheduler_entrypoint, completion_list);

	delete_ready_queue(ready_queue);
}

void *worker_thread_routine(void *ptr)
{
	pid_t pid = register_worker_thread();
	pid_t *pid_ptr = (pid_t *)ptr;
	*pid_ptr = pid;

	worker_wait_for_scheduler();

	printf("Worker %d: start\n", pid);

	printf("Worker %d: before yield\n", pid);
	ums_thread_yield();
	printf("Worker %d: after yield\n", pid);

	printf("Worker %d: end\n", pid);
	worker_thread_terminated();
}

int main(int argc, char *argv[])
{
	ums_completion_list_t *list_1 = create_ums_completion_list();
	ums_completion_list_t *list_2 = create_ums_completion_list();

	pthread_t worker_threads[NUM_WORKER_THREADS];

	for (int i = 0; i < NUM_WORKER_THREADS; i++) {
		pid_t pid = -1;

		pthread_create(&worker_threads[i], NULL, worker_thread_routine, &pid);

		while (pid == -1) {
		};

		enqueue_ums_completion_list(list_1, pid);

		if (i % 2) {
			enqueue_ums_completion_list(list_2, pid);
		}
	}

	while (pthread_key_create(&ready_queue_key, NULL) == EAGAIN) {
	}

	pthread_t scheduler_threads[NUM_SCHEDULER_THREADS];
	for (int i = 0; i < NUM_SCHEDULER_THREADS; i++) {
		ums_completion_list_t *list = list_1;

		if (i % 2) {
			list = list_2;
		}

		pthread_create(&scheduler_threads[i], NULL, scheduler_thread_routine,
									 (void *)list);
	}

	for (int i = 0; i < NUM_WORKER_THREADS; i++) {
		pthread_join(worker_threads[i], NULL);
	}

	for (int i = 0; i < NUM_SCHEDULER_THREADS; i++) {
		pthread_join(scheduler_threads[i], NULL);
	}

	delete_ums_completion_list(list_1);
	delete_ums_completion_list(list_2);

	return EXIT_SUCCESS;
}