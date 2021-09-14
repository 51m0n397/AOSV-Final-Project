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
	int ret;
	pid_t pid = syscall(__NR_gettid);

	ready_queue_t *ready_queue =
		(ready_queue_t *)pthread_getspecific(ready_queue_key);
	if (ready_queue == NULL) {
		perror("Could not get ready queue");
		return;
	}

	if (ready_queue->size == 0) {
		ums_list_node_t *available_thread = NULL;

		ret = dequeue_ums_completion_list_items(&available_thread);
		if (ret < 0) {
			perror("Error while dequeueing worker threads from completion list");
			return;
		}

		while (available_thread != NULL) {
			ret = enqueue_ready_queue(ready_queue, available_thread);
			if (ret < 0) {
				perror("Error while enqueueing worker thread in ready queue");
				return;
			}
			available_thread = get_next_ums_list_item(available_thread);
		}
	}

	while (ready_queue->size > 0) {
		pid_t thread = dequeue_ready_queue(ready_queue);
		if (thread < 0) {
			perror("Error while dequeueing worker thread from ready queue");
			return;
		}
		printf("Scheduler %d: executing thread %d\n", pid, thread);
		ret = execute_ums_thread(thread);
		if (ret < 0) {
			perror("Error while executing worker thread");
			return;
		}
	}
}

void *scheduler_thread_routine(void *ptr)
{
	int ret;
	ums_completion_list_t *completion_list = (ums_completion_list_t *)ptr;

	int *retvalue = (int *)malloc(sizeof(int));
	if (retvalue == NULL) {
		perror("Error while allocating retvalue");
		return NULL;
	}
	*retvalue = EXIT_SUCCESS;

	ready_queue_t *ready_queue = create_ready_queue();
	if (ready_queue == NULL) {
		perror("Error while creating ready queue");
		*retvalue = EXIT_FAILURE;
		return retvalue;
	}

	ret = pthread_setspecific(ready_queue_key, ready_queue);
	if (ret != 0) {
		errno = ret;
		perror("Error while setting ready queue key");
		*retvalue = EXIT_FAILURE;
		return retvalue;
	}

	ret = enter_ums_scheduling_mode(*scheduler_entrypoint, completion_list);
	if (ret < 0) {
		perror("Error while entering ums scheduling mode");
		*retvalue = EXIT_FAILURE;
		return retvalue;
	}

	ret = delete_ready_queue(ready_queue);
	if (ret < 0) {
		perror("Error while deleting ready queue");
		*retvalue = EXIT_FAILURE;
		return retvalue;
	}

	return retvalue;
}

void *worker_thread_routine(void *ptr)
{
	pid_t pid = syscall(__NR_gettid);

	printf("Worker %d: start\n", pid);

	printf("Worker %d: before yield\n", pid);

	int ret = ums_thread_yield();
	if (ret < 0) {
		perror("Error while yielding worker thread");
		return NULL;
	}

	printf("Worker %d: after yield\n", pid);

	printf("Worker %d: end\n", pid);

	return NULL;
}

int main(int argc, char *argv[])
{
	int ret;
	int exitvalue = EXIT_SUCCESS;

	ums_completion_list_t *list_1 = create_ums_completion_list();
	if (list_1 == NULL) {
		perror("Error while creating completion list");
		exit(EXIT_FAILURE);
	}
	ums_completion_list_t *list_2 = create_ums_completion_list();
	if (list_1 == NULL) {
		perror("Error while creating completion list");
		exit(EXIT_FAILURE);
	}

	ums_t worker_threads[NUM_WORKER_THREADS];

	for (int i = 0; i < NUM_WORKER_THREADS; i++) {
		ret = create_ums_thread(&worker_threads[i], worker_thread_routine, NULL);
		if (ret < 0) {
			perror("Error while creating worker thread");
			exit(EXIT_FAILURE);
		}

		ret = pthread_detach(worker_threads[i].pthread_id);
		if (ret != 0) {
			errno = ret;
			perror("Error while detaching worker thread");
			exit(EXIT_FAILURE);
		}

		ret = enqueue_ums_completion_list_item(list_1, worker_threads[i]);
		if (ret < 0) {
			perror("Error while enqueueing worker thread in completion list");
			exit(EXIT_FAILURE);
		}

		if (i % 2) {
			ret = enqueue_ums_completion_list_item(list_2, worker_threads[i]);
			if (ret < 0) {
				perror("Error while enqueueing worker thread in completion list");
				exit(EXIT_FAILURE);
			}
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

		ret = pthread_create(&scheduler_threads[i], NULL, scheduler_thread_routine,
												 (void *)list);
		if (ret != 0) {
			errno = ret;
			perror("Error while creating scheduler thread");
			exit(EXIT_FAILURE);
		}
	}

	for (int i = 0; i < NUM_SCHEDULER_THREADS; i++) {
		void *ptr;
		ret = pthread_join(scheduler_threads[i], &ptr);
		if (ret != 0) {
			errno = ret;
			perror("Error while joining scheduler thread");
			exit(EXIT_FAILURE);
		}
		if (ptr == NULL) {
			exitvalue = EXIT_FAILURE;
		} else {
			if (*(int *)ptr == EXIT_FAILURE)
				exitvalue = EXIT_FAILURE;
			free(ptr);
		}
	}

	delete_ums_completion_list(list_1);
	delete_ums_completion_list(list_2);

	return exitvalue;
}