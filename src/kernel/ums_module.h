#ifndef UMS_MODULE
#define UMS_MODULE

#include <linux/types.h>

#define SUCCESS 0

#define UMS_NEW 0
#define UMS_RUNNING 1
#define UMS_YIELD 2
#define UMS_DEAD 3

#define UMS_SCHED_IDLE 0
#define UMS_SCHED_RUNNING 1

struct worker_thread {
	pid_t id;
	struct rhash_head node;
	struct mutex lock;
	pid_t scheduler;
	int state;
};

struct scheduler_thread {
	pid_t id;
	struct rhash_head node;
	pid_t *completion_list;
	int num_workers;
	pid_t *dequeued_items;
	int num_dequeued_items;
	struct proc_dir_entry *dir;
	pid_t worker;
	int switch_num;
	spinlock_t lock;
};

struct process_proc_dir {
	pid_t id;
	struct rhash_head node;
	int num_schedulers;
	struct proc_dir_entry *pid_dir;
	struct proc_dir_entry *schedulers_dir;
};

int init_module(void);
void cleanup_module(void);
static long device_ioctl(struct file *file, unsigned int request,
												 unsigned long data);

#endif