#ifndef UMS_INTERFACE
#define UMS_INTERFACE

#include <linux/ioctl.h>
#include <linux/major.h>

#define DEVICE_NAME "ums_device"

#define REGISTER_WORKER_THREAD _IO(MISC_MAJOR, 0)
#define WORKER_THREAD_TERMINATED _IO(MISC_MAJOR, 1)
#define EXECUTE_UMS_THREAD _IOW(MISC_MAJOR, 2, pid_t *)

#endif
