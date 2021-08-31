#ifndef UMS_MODULE
#define UMS_MODULE

#include <linux/types.h>

#define SUCCESS 0

typedef struct worker_thread {
	pid_t id;
	struct list_head node;
	pid_t scheduler;
} worker_thread_t;

int init_module(void);
void cleanup_module(void);
static long device_ioctl(struct file *file, unsigned int request,
			 unsigned long data);

#endif