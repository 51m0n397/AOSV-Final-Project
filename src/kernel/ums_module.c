#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "ums_module.h"
#include "ums_interface.h"

#define MODULE_NAME_LOG "UMS: "

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Bartolini <bartolini.1752197@studenti.uniroma1.it>");
MODULE_DESCRIPTION("User Mode Scheduling module");
MODULE_VERSION("1.0.0");

static struct file_operations fops = { .unlocked_ioctl = device_ioctl };

static struct miscdevice mdev = { .minor = 0,
				  .name = DEVICE_NAME,
				  .mode = S_IALLUGO,
				  .fops = &fops };

static LIST_HEAD(worker_threads);
static DEFINE_MUTEX(worker_mutex);

int init_module(void)
{
	int ret;
	printk(KERN_DEBUG MODULE_NAME_LOG "init\n");

	ret = misc_register(&mdev);

	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG
		       "Registering char device failed\n");
		return ret;
	}

	printk(KERN_DEBUG MODULE_NAME_LOG "Device registered successfully\n");

	return SUCCESS;
}

void cleanup_module(void)
{
	misc_deregister(&mdev);

	printk(KERN_DEBUG MODULE_NAME_LOG "exit\n");
}

int __register_worker_thread(pid_t id)
{
	struct worker_thread *worker;

	worker = kzalloc(sizeof(struct worker_thread), GFP_KERNEL);
	if (worker == NULL)
		return -ENOMEM;

	worker->id = id;
	worker->scheduler = -1;
	worker->state = UMS_NEW;
	mutex_init(&worker->lock);

	mutex_lock(&worker_mutex);
	list_add(&worker->node, &worker_threads);
	mutex_unlock(&worker_mutex);

	set_current_state(TASK_KILLABLE);
	schedule();

	return SUCCESS;
}

int __worker_thread_terminated(pid_t id)
{
	struct worker_thread *worker;
	struct task_struct *pcb;

	mutex_lock(&worker_mutex);
	list_for_each_entry (worker, &worker_threads, node) {
		if (worker->id == id)
			break;
	}
	mutex_unlock(&worker_mutex);

	if (worker == NULL) {
		return -ENOENT;
	}

	mutex_lock(&worker->lock);
	pcb = pid_task(find_vpid(worker->scheduler), PIDTYPE_PID);
	worker->state = UMS_DEAD;
	mutex_unlock(&worker->lock);

	wake_up_process(pcb);
	schedule();

	return SUCCESS;
}

int __execute_ums_thread(pid_t sched_id, pid_t worker_id)
{
	struct worker_thread *worker;
	struct task_struct *pcb;
	int ret, state;

	mutex_lock(&worker_mutex);
	list_for_each_entry (worker, &worker_threads, node) {
		if (worker->id == worker_id)
			break;
	}
	mutex_unlock(&worker_mutex);

	if (worker == NULL) {
		return -ENOENT;
	}

	mutex_lock(&worker->lock);
	worker->scheduler = sched_id;
	worker->state = UMS_RUNNING;
	pcb = pid_task(find_vpid(worker->id), PIDTYPE_PID);
	mutex_unlock(&worker->lock);

	wake_up_process(pcb);
	set_current_state(TASK_KILLABLE);
	schedule();

	/* after context switch */
	mutex_lock(&worker->lock);
	state = worker->state;
	mutex_unlock(&worker->lock);

	ret = WORKER_YIELDED;
	if (state == UMS_DEAD) {
		ret = WORKER_TERMINATED;
		mutex_lock(&worker_mutex);
		list_del(&worker->node);
		kfree(worker);
		mutex_unlock(&worker_mutex);
	}

	return ret;
}

int __ums_thread_yield(pid_t id)
{
	struct worker_thread *worker;
	struct task_struct *pcb;

	mutex_lock(&worker_mutex);
	list_for_each_entry (worker, &worker_threads, node) {
		if (worker->id == id)
			break;
	}
	mutex_unlock(&worker_mutex);

	if (worker == NULL) {
		return -ENOENT;
	}

	mutex_lock(&worker->lock);
	pcb = pid_task(find_vpid(worker->scheduler), PIDTYPE_PID);
	worker->state = UMS_YIELD;
	mutex_unlock(&worker->lock);

	wake_up_process(pcb);
	set_current_state(TASK_KILLABLE);
	schedule();

	return SUCCESS;
}

static long device_ioctl(struct file *file, unsigned int request,
			 unsigned long data)
{
	pid_t pid;

	switch (request) {
	case REGISTER_WORKER_THREAD:
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "REGISTER_WORKER_THREAD pid:%d\n",
		       current->pid);

		return __register_worker_thread(current->pid);

	case WORKER_THREAD_TERMINATED:
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "WORKER_THREAD_TERMINATED pid:%d\n",
		       current->pid);

		return __worker_thread_terminated(current->pid);

	case EXECUTE_UMS_THREAD:
		printk(KERN_DEBUG MODULE_NAME_LOG "EXECUTE_UMS_THREAD\n");

		if (copy_from_user(&pid, (pid_t *)data, sizeof(pid_t))) {
			return -EFAULT;
		}
		printk(KERN_DEBUG MODULE_NAME_LOG "scheduler:%d worker:%d\n",
		       current->pid, pid);

		return __execute_ums_thread(current->pid, pid);

	case UMS_THREAD_YIELD:
		printk(KERN_DEBUG MODULE_NAME_LOG "UMS_THREAD_YIELD pid:%d\n",
		       current->pid);

		return __ums_thread_yield(current->pid);
	}

	return -EINVAL;
}