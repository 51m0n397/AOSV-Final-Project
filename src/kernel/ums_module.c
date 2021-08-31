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
DEFINE_MUTEX(list_mutex);

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

static long device_ioctl(struct file *file, unsigned int request,
			 unsigned long data)
{
	pid_t pid;
	worker_thread_t *worker;
	struct task_struct *pcb;

	switch (request) {
	case REGISTER_WORKER_THREAD:
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "REGISTER_WORKER_THREAD pid:%d\n",
		       current->pid);

		worker = kzalloc(sizeof(worker_thread_t), GFP_KERNEL);
		if (worker == NULL)
			return -ENOMEM;

		worker->id = current->pid;
		worker->scheduler = -1;

		mutex_lock(&list_mutex);
		list_add(&worker->node, &worker_threads);
		mutex_unlock(&list_mutex);

		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();

		return SUCCESS;
	case WORKER_THREAD_TERMINATED:
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "WORKER_THREAD_TERMINATED pid:%d\n",
		       current->pid);

		mutex_lock(&list_mutex);
		list_for_each_entry (worker, &worker_threads, node) {
			if (worker->id == current->pid)
				break;
		}

		if (worker == NULL) {
			mutex_unlock(&list_mutex);
			return -ENOENT;
		}

		pcb = pid_task(find_vpid(worker->scheduler), PIDTYPE_PID);

		kfree(worker);
		mutex_unlock(&list_mutex);

		wake_up_process(pcb);
		schedule();

		return SUCCESS;
	case EXECUTE_UMS_THREAD:
		printk(KERN_DEBUG MODULE_NAME_LOG "EXECUTE_UMS_THREAD\n");

		if (copy_from_user(&pid, (pid_t *)data, sizeof(pid_t))) {
			return -EFAULT;
		}
		printk(KERN_DEBUG MODULE_NAME_LOG "scheduler:%d worker:%d\n",
		       current->pid, pid);

		mutex_lock(&list_mutex);
		list_for_each_entry (worker, &worker_threads, node) {
			if (worker->id == pid)
				break;
		}

		if (worker == NULL) {
			mutex_unlock(&list_mutex);
			return -ENOENT;
		}

		worker->scheduler = current->pid;
		pcb = pid_task(find_vpid(worker->id), PIDTYPE_PID);

		mutex_unlock(&list_mutex);

		wake_up_process(pcb);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();

		return SUCCESS;
	}

	return -EINVAL;
}