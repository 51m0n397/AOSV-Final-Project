#ifndef UMS_INTERFACE
#define UMS_INTERFACE

#include <linux/ioctl.h>
#include <linux/major.h>

#define DEVICE_NAME "ums_device"

struct thread_list {
	pid_t *threads;
	int size;
};

#define REGISTER_WORKER_THREAD _IOR(MISC_MAJOR, 0, pid_t *)
#define WORKER_THREAD_TERMINATED _IO(MISC_MAJOR, 1)
#define REGISTER_SCHEDULER_THREAD _IOW(MISC_MAJOR, 2, struct thread_list *)
#define SCHEDULER_THREAD_TERMINATED _IO(MISC_MAJOR, 3)
#define DEQUEUE_UMS_COMPLETION_LIST_ITEMS _IO(MISC_MAJOR, 4)
#define GET_DEQUEUED_ITEMS _IOR(MISC_MAJOR, 5, pid_t *)
#define EXECUTE_UMS_THREAD _IOW(MISC_MAJOR, 6, pid_t *)
#define UMS_THREAD_YIELD _IO(MISC_MAJOR, 7)
#endif
