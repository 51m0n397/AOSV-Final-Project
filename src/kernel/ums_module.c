#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/rwsem.h>

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

const static struct rhashtable_params worker_thread_table_params = {
	.key_len = sizeof(pid_t),
	.key_offset = offsetof(struct worker_thread, id),
	.head_offset = offsetof(struct worker_thread, node),
};

const static struct rhashtable_params scheduler_thread_table_params = {
	.key_len = sizeof(pid_t),
	.key_offset = offsetof(struct scheduler_thread, id),
	.head_offset = offsetof(struct scheduler_thread, node),
};

struct rhashtable worker_threads;
struct rhashtable scheduler_threads;

static DECLARE_RWSEM(worker_lock);

int init_module(void)
{
	int ret;
	printk(KERN_DEBUG MODULE_NAME_LOG "init\n");

	ret = misc_register(&mdev);

	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG "Registering char device failed\n");
		return ret;
	}
	printk(KERN_DEBUG MODULE_NAME_LOG "Device registered successfully\n");

	ret = rhashtable_init(&worker_threads, &worker_thread_table_params);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG "Creating worker thread table failed\n");
		return ret;
	}
	printk(KERN_DEBUG MODULE_NAME_LOG
				 "Worker thread table created successfully\n");

	ret = rhashtable_init(&scheduler_threads, &scheduler_thread_table_params);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG
					 "Creating scheduler thread table failed\n");
		return ret;
	}
	printk(KERN_DEBUG MODULE_NAME_LOG
				 "Scheduler thread table created successfully\n");

	return SUCCESS;
}

void cleanup_module(void)
{
	rhashtable_destroy(&scheduler_threads);
	rhashtable_destroy(&worker_threads);

	misc_deregister(&mdev);

	printk(KERN_DEBUG MODULE_NAME_LOG "exit\n");
}

int __register_worker_thread(pid_t id)
{
	struct worker_thread *worker;
	int ret;

	worker = kzalloc(sizeof(struct worker_thread), GFP_KERNEL);
	if (worker == NULL)
		return -ENOMEM;

	worker->id = id;
	worker->scheduler = -1;
	worker->state = UMS_NEW;
	mutex_init(&worker->lock);

	down_write(&worker_lock);
	ret = rhashtable_lookup_insert_fast(&worker_threads, &worker->node,
																			worker_thread_table_params);
	up_write(&worker_lock);

	if (ret < 0) {
		kfree(worker);
		return ret;
	}

	return id;
}

int __worker_wait_for_scheduler(void)
{
	set_current_state(TASK_KILLABLE);
	schedule();

	return SUCCESS;
}

int __worker_thread_terminated(pid_t id)
{
	struct worker_thread *worker;
	struct task_struct *pcb;
	int wake = 0;

	down_read(&worker_lock);

	worker =
		rhashtable_lookup_fast(&worker_threads, &id, worker_thread_table_params);

	if (worker == NULL) {
		up_read(&worker_lock);
		return -ENOENT;
	}

	mutex_lock(&worker->lock);
	pcb = pid_task(find_vpid(worker->scheduler), PIDTYPE_PID);
	worker->state = UMS_DEAD;
	mutex_unlock(&worker->lock);

	up_read(&worker_lock);

	printk(KERN_DEBUG MODULE_NAME_LOG "worker:%d waking scheduler:%d\n", id,
				 worker->scheduler);

	while (wake != 1) {
		wake = wake_up_process(pcb);
	}
	schedule();

	return SUCCESS;
}

int __register_scheduler_thread(pid_t id, struct thread_list *completion_list)
{
	struct scheduler_thread *scheduler;
	int ret, i;

	scheduler = kzalloc(sizeof(struct scheduler_thread), GFP_KERNEL);
	if (scheduler == NULL)
		return -ENOMEM;

	scheduler->id = id;
	scheduler->dequeued_items = NULL;
	scheduler->num_dequeued_items = 0;

	scheduler->completion_list =
		kcalloc(completion_list->size, sizeof(pid_t), GFP_KERNEL);
	if (scheduler->completion_list == NULL) {
		kfree(scheduler);
		return -ENOMEM;
	}
	if (copy_from_user(scheduler->completion_list, completion_list->threads,
										 completion_list->size * sizeof(pid_t))) {
		kfree(scheduler->completion_list);
		kfree(scheduler);
		return -EFAULT;
	}
	scheduler->num_workers = completion_list->size;

	for (i = 0; i < scheduler->num_workers; i++) {
		printk(KERN_DEBUG MODULE_NAME_LOG
					 "scheduler %d completion list: worker %d\n",
					 id, scheduler->completion_list[i]);
	}

	ret = rhashtable_lookup_insert_fast(&scheduler_threads, &scheduler->node,
																			scheduler_thread_table_params);

	if (ret < 0) {
		kfree(scheduler->completion_list);
		kfree(scheduler);
		return ret;
	}

	return SUCCESS;
}

int __scheduler_thread_terminated(pid_t id)
{
	struct scheduler_thread *scheduler;

	scheduler = rhashtable_lookup_fast(&scheduler_threads, &id,
																		 scheduler_thread_table_params);

	if (scheduler == NULL) {
		return -ENOENT;
	}

	rhashtable_remove_fast(&scheduler_threads, &scheduler->node,
												 scheduler_thread_table_params);
	kfree(scheduler);

	return SUCCESS;
}

int __dequeue_ums_completion_list_items(pid_t scheduler_id)
{
	struct scheduler_thread *scheduler;
	struct worker_thread *worker;
	int i, found;

	scheduler = rhashtable_lookup_fast(&scheduler_threads, &scheduler_id,
																		 scheduler_thread_table_params);
	if (scheduler == NULL)
		return -ENOENT;

	if (scheduler->num_dequeued_items > 0)
		return -EPERM;

	scheduler->dequeued_items =
		kcalloc(scheduler->num_workers, sizeof(pid_t), GFP_KERNEL);
	if (scheduler->dequeued_items == NULL)
		return -ENOMEM;

	while (scheduler->num_dequeued_items == 0) {
		found = 0;
		for (i = 0; i < scheduler->num_workers; i++) {
			down_read(&worker_lock);

			worker =
				rhashtable_lookup_fast(&worker_threads, &scheduler->completion_list[i],
															 worker_thread_table_params);

			if (worker != NULL) {
				mutex_lock(&worker->lock);
				if (worker->state != UMS_DEAD) {
					found++;
					if (worker->scheduler == -1) {
						worker->scheduler = scheduler_id;
						scheduler->dequeued_items[scheduler->num_dequeued_items++] =
							worker->id;

						printk(KERN_DEBUG MODULE_NAME_LOG
									 "scheduler:%d dequeued worker:%d\n",
									 scheduler_id, worker->id);
					}
				}
				mutex_unlock(&worker->lock);
			}

			up_read(&worker_lock);
		}

		if (found == 0) {
			/* all workers terminated */
			kfree(scheduler->dequeued_items);
			break;
		}
	}

	return scheduler->num_dequeued_items;
}

int __get_dequeued_items(pid_t scheduler_id, pid_t *output_list)
{
	struct scheduler_thread *scheduler;

	scheduler = rhashtable_lookup_fast(&scheduler_threads, &scheduler_id,
																		 scheduler_thread_table_params);
	if (scheduler == NULL)
		return -ENOENT;

	if (copy_to_user(output_list, scheduler->dequeued_items,
									 sizeof(pid_t) * scheduler->num_dequeued_items))
		return -EFAULT;

	kfree(scheduler->dequeued_items);
	scheduler->num_dequeued_items = 0;

	return SUCCESS;
}

int __execute_ums_thread(pid_t sched_id, pid_t worker_id)
{
	struct worker_thread *worker;
	struct task_struct *pcb;
	int state;
	int wake = 0;

	down_read(&worker_lock);

	worker = rhashtable_lookup_fast(&worker_threads, &worker_id,
																	worker_thread_table_params);

	if (worker == NULL) {
		up_read(&worker_lock);
		return -ENOENT;
	}

	printk(KERN_DEBUG MODULE_NAME_LOG "scheduler:%d executing worker:%d\n",
				 sched_id, worker_id);

	mutex_lock(&worker->lock);
	worker->state = UMS_RUNNING;
	pcb = pid_task(find_vpid(worker->id), PIDTYPE_PID);
	mutex_unlock(&worker->lock);

	up_read(&worker_lock);

	while (wake != 1) {
		wake = wake_up_process(pcb);
	}
	set_current_state(TASK_KILLABLE);
	schedule();

	/* after context switch */
	printk(KERN_DEBUG MODULE_NAME_LOG "Back from switch:%d\n", sched_id);

	mutex_lock(&worker->lock);
	state = worker->state;
	mutex_unlock(&worker->lock);

	if (state == UMS_DEAD) {
		down_write(&worker_lock);
		rhashtable_remove_fast(&worker_threads, &worker->node,
													 worker_thread_table_params);
		kfree(worker);
		up_write(&worker_lock);
	} else {
		mutex_lock(&worker->lock);
		worker->scheduler = -1;
		mutex_unlock(&worker->lock);
	}

	return SUCCESS;
}

int __ums_thread_yield(pid_t id)
{
	struct worker_thread *worker;
	struct task_struct *pcb;
	int wake = 0;

	down_read(&worker_lock);
	worker =
		rhashtable_lookup_fast(&worker_threads, &id, worker_thread_table_params);

	if (worker == NULL)
		return -ENOENT;

	mutex_lock(&worker->lock);
	pcb = pid_task(find_vpid(worker->scheduler), PIDTYPE_PID);
	worker->state = UMS_YIELD;
	mutex_unlock(&worker->lock);

	up_read(&worker_lock);

	printk(KERN_DEBUG MODULE_NAME_LOG "worker:%d waking scheduler:%d\n", id,
				 worker->scheduler);

	while (wake != 1) {
		wake = wake_up_process(pcb);
	}

	set_current_state(TASK_KILLABLE);
	schedule();

	return SUCCESS;
}

static long device_ioctl(struct file *file, unsigned int request,
												 unsigned long data)
{
	pid_t pid;
	struct thread_list list;

	switch (request) {
	case REGISTER_WORKER_THREAD:
		printk(KERN_DEBUG MODULE_NAME_LOG "REGISTER_WORKER_THREAD pid:%d\n",
					 current->pid);

		return __register_worker_thread(current->pid);

	case WORKER_WAIT_FOR_SCHEDULER:
		printk(KERN_DEBUG MODULE_NAME_LOG "WORKER_WAIT_FOR_SCHEDULER pid:%d\n",
					 current->pid);

		return __worker_wait_for_scheduler();

	case WORKER_THREAD_TERMINATED:
		printk(KERN_DEBUG MODULE_NAME_LOG "WORKER_THREAD_TERMINATED pid:%d\n",
					 current->pid);

		return __worker_thread_terminated(current->pid);

	case REGISTER_SCHEDULER_THREAD:
		printk(KERN_DEBUG MODULE_NAME_LOG "REGISTER_SCHEDULER_THREAD pid:%d\n",
					 current->pid);

		if (copy_from_user(&list, (struct thread_list *)data,
											 sizeof(struct thread_list)))
			return -EFAULT;

		return __register_scheduler_thread(current->pid, &list);

	case SCHEDULER_THREAD_TERMINATED:
		printk(KERN_DEBUG MODULE_NAME_LOG "SCHEDULER_THREAD_TERMINATED pid:%d\n",
					 current->pid);

		return __scheduler_thread_terminated(current->pid);

	case DEQUEUE_UMS_COMPLETION_LIST_ITEMS:
		printk(KERN_DEBUG MODULE_NAME_LOG
					 "DEQUEUE_UMS_COMPLETION_LIST_ITEMS pid:%d\n",
					 current->pid);

		return __dequeue_ums_completion_list_items(current->pid);

	case GET_DEQUEUED_ITEMS:
		printk(KERN_DEBUG MODULE_NAME_LOG "GET_DEQUEUED_ITEMS pid:%d\n",
					 current->pid);

		return __get_dequeued_items(current->pid, (pid_t *)data);

	case EXECUTE_UMS_THREAD:
		printk(KERN_DEBUG MODULE_NAME_LOG "EXECUTE_UMS_THREAD pid:%d\n",
					 current->pid);

		if (copy_from_user(&pid, (pid_t *)data, sizeof(pid_t)))
			return -EFAULT;

		return __execute_ums_thread(current->pid, pid);

	case UMS_THREAD_YIELD:
		printk(KERN_DEBUG MODULE_NAME_LOG "UMS_THREAD_YIELD pid:%d\n",
					 current->pid);

		return __ums_thread_yield(current->pid);
	}

	return -EINVAL;
}