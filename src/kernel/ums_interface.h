#ifndef UMS_INTERFACE
#define UMS_INTERFACE

#include <linux/ioctl.h>
#include <linux/major.h>

#define DEVICE_NAME "ums_device"

#define WORKER_YIELDED 1
#define WORKER_TERMINATED 2

#define REGISTER_WORKER_THREAD _IO(MISC_MAJOR, 0)
#define WORKER_THREAD_TERMINATED _IO(MISC_MAJOR, 1)
#define EXECUTE_UMS_THREAD _IOW(MISC_MAJOR, 2, pid_t *)
#define UMS_THREAD_YIELD _IO(MISC_MAJOR, 3)

#endif
