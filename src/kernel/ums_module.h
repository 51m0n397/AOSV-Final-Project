#ifndef UMS_MODULE
#define UMS_MODULE

#include <linux/types.h>

#define SUCCESS 0

#define UMS_NEW 0
#define UMS_RUNNING 1
#define UMS_YIELD 2
#define UMS_DEAD 3

struct worker_thread {
	pid_t id;
	struct rhash_head node;
	struct mutex lock;
	pid_t scheduler;
	int state;
};

int init_module(void);
void cleanup_module(void);
static long device_ioctl(struct file *file, unsigned int request,
			 unsigned long data);

#endif