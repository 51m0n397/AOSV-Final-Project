/**
 * @file ums.h
 * @author Simone Bartolini
 * @brief User Mode Scheduling library. To be used in congiuntion with the UMS
 *        kernel module to be able to schedule threads without involving the
 *        kernel scheduler.
 */

#ifndef _UMS_H
#define _UMS_H

#include <sys/types.h>
#include <pthread.h>

/**
 * @brief Struct representing a UMS worker thread.
 */
typedef struct ums {
	/**
	 * The PID of the worker thread. It is used by the UMS module for
	 * scheduling.
	 */
	pid_t		pid;
	/**
	 * The ptread ID of the worker thread. It is used for joining, detaching
	 * or doing any other operations using the functions from the pthread
	 * library.
	 */
	pthread_t	pthread_id;
} ums_t;

/**
 * @brief Node of a UMS workers list.
 */
typedef struct ums_list_node {
	pid_t			thread;	/**< The PID of the worker thread. */
	struct ums_list_node	*next;	/**< The next node in the list. */
} ums_list_node_t;

/**
 * @brief A list of UMS worker threads.
 */
struct ums_list {
	ums_list_node_t	*head;	/**<  The first element in the list. */
	ums_list_node_t	*tail;	/**<  The last element in the list. */
	int		size;	/**<  The number of elements in the list. */
};

/**
 * @brief A UMS scheduler completion list.
 */
typedef struct ums_list ums_completion_list_t;

/**
 * @brief A UMS scheduler ready queue.
 */
typedef struct ums_list ready_queue_t;

/**
 * @brief A UMS scheduler entry point function.
 */
typedef void (*scheduler_entrypoint_t)();

/**
 * @brief   Creates a UMS worker thread. The newly created thread will not start
 *          executing until it is scheduled by a UMS scheduler.
 *
 * @param   thread         A pointer to a ::ums_t variable that will be
 *                         populated with the IDs of the newly created thread.
 *
 * @param   start_routine  A pointer to the function to be executed by the newly
 *                         created thread.
 *
 * @param   arg            An argument to be passed to the \a start_routine
 *                         function.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ENOSYS]: The UMS module is not loaded.
 *  - [ENOMEM]: Not enough memory.
 *  - [EAGAIN]: Insufficient resources to create another thread.
 *  - [EAGAIN]: A system-imposed limit on the number of threads was encountered.
 */
int create_ums_thread(ums_t *thread, void *(*start_routine)(void *), void *arg);

/**
 * @brief   Converts the calling thread into a UMS scheduler thread.
 *
 * @param   entrypoint       A pointer to a ::scheduler_entrypoint_t entry point
 *                           function that will be called by the scheduler to
 *                           select the next worker thread to be executed.
 *
 * @param   completion_list  A pointer to a ::ums_completion_list_t variable
 *                           containing the list of worker threads to be
 * scheduled.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ENOSYS]: The UMS module is not loaded.
 *  - [EINVAL]: \a entrypoint is not a valid function.
 *  - [EINVAL]: \a completion_list is not a valid completion list or it is
 *              empty.
 *  - [ENOMEM]: Not enough memory.
 *  - [EEXIST]: Scheduler alredy registered. This can only happen if you are
 *              calling this function inside the entry point function of an
 *              already registered scheduler.
 */
int enter_ums_scheduling_mode(scheduler_entrypoint_t entrypoint,
			      ums_completion_list_t *completion_list);

/**
 * @brief   Creates a UMS scheduler completion list.
 *
 * @return  A pointer to the newly created completion list on success, NULL on
 *          error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ENOMEM]: Not enough memory.
 */
ums_completion_list_t *create_ums_completion_list();

/**
 * @brief  Deletes the specified UMS scheduler completion list.
 *
 * @param  completion_list  A pointer to the completion list to be deleted.
 */
void delete_ums_completion_list(ums_completion_list_t *completion_list);

/**
 * @brief   Enqueues a UMS worker thread inside a UMS completion list.
 *
 * @param   completion_list  A pointer to the completion list in which to
 *                           enqueue the worker thread.
 *
 * @param   thread           A ::ums_t variable containing the IDs of the worker
 *                           thread to be enqueued.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  -  [EINVAL]: \a completion_list is not a valid completion list.
 *  -  [ESRCH]:  \a thread is not a valid UMS worker thread.
 *  - [ENOMEM]:  Not enough memory.
 */
int enqueue_ums_completion_list_item(ums_completion_list_t *completion_list,
				     ums_t thread);

/**
 * @brief   Executes the specified UMS worker thread.
 *
 * @param   thread  The PID of the worker thread to be executed.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ENOSYS]: The UMS module is not loaded.
 *  - [ESRCH]:  \a thread is not a valid UMS worker thread.
 *  - [ESRCH]:  The calling process is not a UMS scheduler thread.
 */
int execute_ums_thread(pid_t thread);

/**
 * @brief   Retrieves the list of ready UMS worker threads inside the completion
 *          list of the calling UMS scheduler thread. It blocks until it either
 *          finds at lest one ready worker thread or all worker threads
 *          terminated.
 *
 * @param   list  A pointer to a ::ums_list_node_t pointer. Once the function
 *                returns it will point to the first element of the list of
 *                ready worker threads, unless all worker threads terminated.
 *
 * @return  The number of worker thread dequeued on success, -1 on error, errno
 * will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ENOSYS]: The UMS module is not loaded.
 *  - [EINVAL]: \a list is not a valid pointer.
 *  - [ESRCH]:  The calling process is not a UMS scheduler thread.
 *  - [ENOMEM]: Not enough memory.
 */
int dequeue_ums_completion_list_items(ums_list_node_t **list);

/**
 * @brief   Retrieves the next element in a list of ready worker threads and
 *          frees the current one.
 *
 * @param   item  A pointer to a ::ums_list_node_t in a list of ready worker
 *                threads.
 *
 * @return  A pointer to the next element in the list, if there is one, NULL
 *          otherwise.
 */
ums_list_node_t *get_next_ums_list_item(ums_list_node_t *item);

/**
 * @brief   Yields the CPU from the calling UMS worker thread and to the UMS
 *          scheduler thread that executed it. The scheduler will execute the
 *          entry point function to select the next worker to be runned.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ENOSYS]: The UMS module is not loaded.
 *  - [ESRCH]:  The calling process is not a UMS worker thread.
 */
int ums_thread_yield();

/**
 * @brief   Creates a UMS scheduler ready queue.
 *
 * @return  A pointer to the newly created ready queue on success, NULL on
 *          error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ENOMEM]: Not enough memory.
 */
ready_queue_t *create_ready_queue();

/**
 * @brief   Deletes the specified UMS scheduler ready queue. The queue must be
 *          empty.
 *
 * @param   ready_queue  A pointer to the ready queue to be deleted.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [EINVAL]:    \a ready_queue is not a valid pointer.
 *  - [ENOTEMPTY]: The queue is not empty.
 */
int delete_ready_queue(ready_queue_t *ready_queue);

/**
 * @brief   Enqueues a UMS worker thread inside a ready queue.
 *
 * @param   ready_queue  A pointer to the ready queue in which to equeue the
 *                       worker thread.
 * @param   item         A pointer to the an element of a ready thread list
 *                       retrieved by calling
 *                       ::dequeue_ums_completion_list_items.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [EINVAL]: \a ready_queue is not a valid pointer.
 *  - [EINVAL]: \a item is not a valid pointer.
 *  - [ENOMEM]: Not enough memory.
 */
int enqueue_ready_queue(ready_queue_t *ready_queue, ums_list_node_t *item);

/**
 * @brief   Dequeues a UMS worker thread from a ready queue.
 *
 * @param   ready_queue  A pointer to the ready queue from which to dequeue the
 *                       worker thread.
 *
 * @return  The PID of the dequeued worker on success, -1 on error, errno will
 *          contain the error code.
 *
 * <b> Error codes </b>
 *  - [EINVAL]: \a ready_queue is not a valid pointer.
 *  - [EINVAL]: \a ready_queue points to an empty queue.
 */
pid_t dequeue_ready_queue(ready_queue_t *ready_queue);

#endif /* _UMS_H */