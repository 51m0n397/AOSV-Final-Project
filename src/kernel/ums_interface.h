/**
 * @file ums_interface.h
 * @author Simone Bartolini
 * @brief User Mode Scheduling kernel module interface. It defines the ioctl
 *        request numbers to be used to communicate with the module.
 */

#ifndef _UMS_INTERFACE_H
#define _UMS_INTERFACE_H

#ifndef __KERNEL__
/* Includes for userspace */
#include <sys/ioctl.h>
#include <sys/types.h>
#else
/* Includes for kernel */
#include <linux/ioctl.h>
#include <linux/types.h>
#endif

/**
 * @brief The name of the virtual device defined by the UMS module.
 */
#define DEVICE_NAME "ums_device"

/* \cond DO_NOT_DOCUMENT */
#define UMS_MAGIC   0x01
/* \endcond */

/**
 * @brief Struct used to pass the completion list to the module.
 */
struct thread_list {
	pid_t	*threads;	/**< Array of pid_t */
	int	size;		/**< Number of elements in the array */
};

/**
 * @brief   Registers the calling thread as a UMS worker thread and sets the
 *          pid_t variable pointed by the passed pointer to its PID.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [EEXIST]: Thread already registered.
 *  - [EFAULT]: Invalid address.
 *  - [ENOMEM]: Not enough memory.
 **/
#define REGISTER_WORKER_THREAD		  _IOR(UMS_MAGIC, 0, pid_t *)

/**
 * @brief   Signals to the module that the calling UMS worker thread has
 *          terminated so that it can wake the scheduler that executed it.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ESRCH]: The calling process is not a registered UMS worker thread.
 **/
#define WORKER_THREAD_TERMINATED	  _IO(UMS_MAGIC, 1)

/**
 * @brief   Registers the calling thread as a UMS scheduler thread with
 *          completion list equal to the one passed in the struct thread_list.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [EEXIST]: Thread already registered.
 *  - [EFAULT]: Invalid address passed in input.
 *  - [ENOMEM]: Not enough memory.
 **/
#define REGISTER_SCHEDULER_THREAD	  _IOW(UMS_MAGIC, 2, struct thread_list *)

/**
 * @brief   Scans the completion list of the calling UMS scheduler thread to
 *          check if there are UMS worker threads ready to be executed. Blocks
 *          until there is at least one ready worker thread, unless all worker
 *          threads terminated. Use ::GET_DEQUEUED_ITEMS to retrieve the list of
 *          ready worker threads.
 *
 * @return  The number of UMS worker threads found on success, -1 on error,
 *          errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ESRCH]:  The calling process is not a registered UMS scheduler thread.
 *  - [EPERM]:  You are not allowed to call ::DEQUEUE_UMS_COMPLETION_LIST_ITEMS
 *              again without calling ::GET_DEQUEUED_ITEMS first.
 *  - [ENOMEM]: Not enough memory.
 *  - [EINTR]:  Operation interrupted by fatal signal.
 **/
#define DEQUEUE_UMS_COMPLETION_LIST_ITEMS _IO(UMS_MAGIC, 3)

/**
 * @brief   Retrieves the list of ready UMS worker threads found by a previous
 *          call to ::DEQUEUE_UMS_COMPLETION_LIST_ITEMS. You need to pass in
 *          input an array of pid_t of size equal to the number of worker
 *          threads returned by ::DEQUEUE_UMS_COMPLETION_LIST_ITEMS. The array
 *          will be populated with the PIDs of the dequeued workers.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ESRCH]:  The calling process is not a registered UMS scheduler thread.
 *  - [EFAULT]: Invalid address passed in input.
 **/
#define GET_DEQUEUED_ITEMS		  _IOR(UMS_MAGIC, 4, pid_t *)

/**
 * @brief   Executes the UMS worker thread with PID equal to the pid_t variable
 *          pointed by the pointer passed in input.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ESRCH]: The calling process is not a registered UMS scheduler thread.
 *  - [ESRCH]: The passed PID does not correspond to a registered UMS worker
 *             thread.
 **/
#define EXECUTE_UMS_THREAD		  _IOW(UMS_MAGIC, 5, pid_t *)

/**
 * @brief   Yields the CPU from the calling UMS worker thread and to the UMS
 *          scheduler thread that executed it.
 *
 * @return  0 on success, -1 on error, errno will contain the error code.
 *
 * <b> Error codes </b>
 *  - [ESRCH]: The calling process is not a registered UMS worker thread.
 **/
#define UMS_THREAD_YIELD		  _IO(UMS_MAGIC, 6)

#endif /* _UMS_INTERFACE_H */
