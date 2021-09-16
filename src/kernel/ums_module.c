#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/rwsem.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

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

const static struct rhashtable_params proc_directiory_table_params = {
	.key_len = sizeof(pid_t),
	.key_offset = offsetof(struct process_proc_dir, id),
	.head_offset = offsetof(struct process_proc_dir, node),
};

struct rhashtable worker_threads;
struct rhashtable scheduler_threads;
struct rhashtable proc_directories;

static DECLARE_RWSEM(worker_lock);
static DEFINE_MUTEX(proc_directory_lock);

static struct proc_dir_entry *ums_dir;

static int scheduler_open(struct inode *inode, struct file *file);
static struct proc_ops scheduler_fops = { .proc_open = scheduler_open,
																					.proc_read = seq_read,
																					.proc_release = single_release };

static int worker_open(struct inode *inode, struct file *file);
static struct proc_ops worker_fops = { .proc_open = worker_open,
																			 .proc_read = seq_read,
																			 .proc_release = single_release };

int init_module(void)
{
	int ret;
	printk(KERN_DEBUG MODULE_NAME_LOG "Initializing module\n");

	ret = misc_register(&mdev);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG "Registering misc device failed\n");
		goto fail_mdev;
	}

	ret = rhashtable_init(&worker_threads, &worker_thread_table_params);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG "Creating worker thread table failed\n");
		goto fail_worker_threads;
	}

	ret = rhashtable_init(&scheduler_threads, &scheduler_thread_table_params);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG
					 "Creating scheduler thread table failed\n");
		goto fail_scheduler_threads;
	}

	ret = rhashtable_init(&proc_directories, &proc_directiory_table_params);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG "Creating proc directory table failed\n");
		goto fail_proc_directories;
	}

	ums_dir = proc_mkdir("ums", NULL);
	if (!ums_dir) {
		printk(KERN_ALERT MODULE_NAME_LOG "Creating ums proc folder failed\n");
		ret = -ENOMEM;
		goto fail_ums_dir;
	}

	printk(KERN_DEBUG MODULE_NAME_LOG "Module intialized successfully\n");

	return SUCCESS;

fail_ums_dir:
	rhashtable_destroy(&proc_directories);
fail_proc_directories:
	rhashtable_destroy(&scheduler_threads);
fail_scheduler_threads:
	rhashtable_destroy(&worker_threads);
fail_worker_threads:
	misc_deregister(&mdev);
fail_mdev:
	return ret;
}

void cleanup_module(void)
{
	proc_remove(ums_dir);
	rhashtable_destroy(&proc_directories);
	rhashtable_destroy(&scheduler_threads);
	rhashtable_destroy(&worker_threads);
	misc_deregister(&mdev);

	printk(KERN_DEBUG MODULE_NAME_LOG "Module unregistered\n");
}

static int scheduler_show(struct seq_file *m, void *v)
{
	int i;
	struct scheduler_thread *scheduler = m->private;

	spin_lock(&scheduler->lock);

	seq_printf(m, "Pid:\t %d\n", scheduler->id);
	seq_printf(m, "Completion list:\n");
	for (i = 0; i < scheduler->num_workers; i++) {
		seq_printf(m, "\t %d)\t %d\n", i, scheduler->completion_list[i]);
	}
	if (scheduler->worker == -1)
		seq_printf(m, "State:\t Idle\n");
	else {
		seq_printf(m, "State:\t Running\n");
		seq_printf(m, "Worker:\t %d\n", scheduler->worker);
	}
	seq_printf(m, "Number of switches:\t %d\n", scheduler->switch_num);

	spin_unlock(&scheduler->lock);

	return SUCCESS;
}

static int scheduler_open(struct inode *inode, struct file *file)
{
	return single_open(file, scheduler_show, PDE_DATA(inode));
}

static int worker_show(struct seq_file *m, void *v)
{
	struct worker_thread *worker;
	int *id = m->private;

	seq_printf(m, "Pid:\t %d\n", *id);

	down_read(&worker_lock);

	worker =
		rhashtable_lookup_fast(&worker_threads, id, worker_thread_table_params);
	if (worker != NULL) {
		spin_lock(&worker->lock);

		if (worker->state == UMS_RUNNING) {
			seq_printf(m, "State:\t Running\n");
			seq_printf(m, "Scheduler:\t %d\n", worker->scheduler);
		} else {
			seq_printf(m, "State:\t Idle\n");
		}
		seq_printf(m, "Number of switches:\t %d\n", worker->switch_num);

		spin_unlock(&worker->lock);
	} else {
		seq_printf(m, "State:\t Terminated\n");
	}

	up_read(&worker_lock);

	return SUCCESS;
}

static int worker_open(struct inode *inode, struct file *file)
{
	return single_open(file, worker_show, PDE_DATA(inode));
}

struct process_proc_dir *create_process_proc_dir(pid_t pid)
{
	int ret;
	char id[12];
	struct process_proc_dir *dir, *err;

	dir = kzalloc(sizeof(struct process_proc_dir), GFP_KERNEL);
	if (dir == NULL) {
		err = ERR_PTR(-ENOMEM);
		goto fail_alloc;
	}

	dir->id = pid;
	dir->num_schedulers = 0;
	dir->last_sched_id = 0;

	sprintf(id, "%d", pid);
	dir->pid_dir = proc_mkdir(id, ums_dir);
	if (dir->pid_dir == NULL) {
		err = ERR_PTR(-ENOMEM);
		goto fail_mk_pid_dir;
	}

	dir->schedulers_dir = proc_mkdir("schedulers", dir->pid_dir);
	if (dir->schedulers_dir == NULL) {
		err = ERR_PTR(-ENOMEM);
		goto fail_mk_schedulers_dir;
	}

	ret = rhashtable_insert_fast(&proc_directories, &dir->node,
															 proc_directiory_table_params);
	if (ret < 0) {
		err = ERR_PTR(ret);
		goto fail_insert;
	}

	return dir;

fail_insert:
	proc_remove(dir->schedulers_dir);
fail_mk_schedulers_dir:
	proc_remove(dir->pid_dir);
fail_mk_pid_dir:
	kfree(dir);
fail_alloc:
	return err;
}

void remove_process_proc_dir(struct process_proc_dir *dir)
{
	rhashtable_remove_fast(&proc_directories, &dir->node,
												 proc_directiory_table_params);
	proc_remove(dir->schedulers_dir);
	proc_remove(dir->pid_dir);
	kfree(dir);
}

int __register_worker_thread(pid_t id, pid_t *user_id)
{
	struct worker_thread *worker;
	int ret;

	worker = kzalloc(sizeof(struct worker_thread), GFP_KERNEL);
	if (worker == NULL) {
		ret = -ENOMEM;
		goto fail_alloc;
	}

	worker->id = id;
	worker->scheduler = -1;
	worker->state = UMS_NEW;
	worker->switch_num = 0;
	spin_lock_init(&worker->lock);

	down_write(&worker_lock);
	ret = rhashtable_lookup_insert_fast(&worker_threads, &worker->node,
																			worker_thread_table_params);
	if (ret < 0)
		goto fail_insert;

	if (copy_to_user(user_id, &id, sizeof(pid_t))) {
		ret = -EFAULT;
		goto fail_copy;
	}

	up_write(&worker_lock);

	set_current_state(TASK_KILLABLE);
	schedule();

	return SUCCESS;

fail_copy:
	rhashtable_remove_fast(&worker_threads, &worker->node,
												 worker_thread_table_params);
fail_insert:
	up_write(&worker_lock);
	kfree(worker);
fail_alloc:
	return ret;
}

int __worker_thread_terminated(pid_t id)
{
	struct worker_thread *worker;
	struct task_struct *pcb;

	down_read(&worker_lock);

	worker =
		rhashtable_lookup_fast(&worker_threads, &id, worker_thread_table_params);

	if (worker == NULL) {
		up_read(&worker_lock);
		return -ENOENT;
	}

	spin_lock(&worker->lock);
	pcb = pid_task(find_vpid(worker->scheduler), PIDTYPE_PID);
	worker->state = UMS_DEAD;
	spin_unlock(&worker->lock);

	up_read(&worker_lock);

	down_write(&worker_lock);
	rhashtable_remove_fast(&worker_threads, &worker->node,
												 worker_thread_table_params);
	kfree(worker);
	up_write(&worker_lock);

	printk(KERN_DEBUG MODULE_NAME_LOG "worker:%d waking scheduler:%d\n", id,
				 pcb->pid);

	wake_up_process(pcb);
	schedule();

	return SUCCESS;
}

int __register_scheduler_thread(pid_t scheduler_id, pid_t process_id,
																struct thread_list *completion_list)
{
	struct scheduler_thread *scheduler;
	struct process_proc_dir *process_dir;
	char index[12];
	int ret, i;

	/* Allocating scheduler struct */
	scheduler = kzalloc(sizeof(struct scheduler_thread), GFP_KERNEL);
	if (scheduler == NULL) {
		ret = -ENOMEM;
		goto fail_scheduler_alloc;
	}

	scheduler->id = scheduler_id;
	scheduler->dequeued_items = NULL;
	scheduler->num_dequeued_items = 0;
	scheduler->num_workers = completion_list->size;
	scheduler->worker = -1;
	scheduler->switch_num = 0;
	spin_lock_init(&scheduler->lock);

	/* Allocating completion list */
	scheduler->completion_list =
		kcalloc(completion_list->size, sizeof(pid_t), GFP_KERNEL);
	if (scheduler->completion_list == NULL) {
		ret = -ENOMEM;
		goto fail_completion_list_alloc;
	}

	/* Copying completion list from user */
	if (copy_from_user(scheduler->completion_list, completion_list->threads,
										 completion_list->size * sizeof(pid_t))) {
		ret = -EFAULT;
		goto fail_copy_from_user;
	}
	for (i = 0; i < scheduler->num_workers; i++) {
		printk(KERN_DEBUG MODULE_NAME_LOG
					 "scheduler %d completion list: worker %d\n",
					 scheduler_id, scheduler->completion_list[i]);
	}

	/* 
	 * Creating proc directory for the scheduler. 
	 * We first check if the process proc directory already exists, otherwise we
	 * create it.
	*/
	mutex_lock(&proc_directory_lock);
	process_dir = rhashtable_lookup_fast(&proc_directories, &process_id,
																			 proc_directiory_table_params);
	if (process_dir == NULL)
		process_dir = create_process_proc_dir(process_id);

	if (IS_ERR(process_dir)) {
		ret = PTR_ERR(process_dir);
		goto fail_process_dir;
	}

	process_dir->num_schedulers++;
	sprintf(index, "%d", process_dir->last_sched_id++);
	scheduler->dir = proc_mkdir(index, process_dir->schedulers_dir);
	if (scheduler->dir == NULL) {
		ret = -ENOMEM;
		goto fail_dir;
	}
	mutex_unlock(&proc_directory_lock);

	/* Creating scheduler info file */
	if (!proc_create_data("info", 0, scheduler->dir, &scheduler_fops,
												scheduler)) {
		ret = -ENOMEM;
		goto fail_scheduler_info;
	}

	/* Creating workers directory */
	scheduler->workers_dir = proc_mkdir("workers", scheduler->dir);
	if (scheduler->workers_dir == NULL) {
		ret = -ENOMEM;
		goto fail_workers_dir;
	}

	/* Creating workers info files */
	for (i = 0; i < scheduler->num_workers; i++) {
		sprintf(index, "%d", i);
		if (!proc_create_data(index, 0, scheduler->workers_dir, &worker_fops,
													&scheduler->completion_list[i])) {
			ret = -ENOMEM;
			goto fail_worker_info;
		}
	}

	/* Inserting scheduler in the table */
	ret = rhashtable_lookup_insert_fast(&scheduler_threads, &scheduler->node,
																			scheduler_thread_table_params);
	if (ret < 0)
		goto fail_insert;

	return SUCCESS;

fail_insert:
fail_worker_info:
	while (i > 0) {
		sprintf(index, "%d", --i);
		remove_proc_entry(index, scheduler->workers_dir);
	}
	proc_remove(scheduler->workers_dir);
fail_workers_dir:
	remove_proc_entry("info", scheduler->dir);
fail_scheduler_info:
	mutex_lock(&proc_directory_lock);
	proc_remove(scheduler->dir);
fail_dir:
	process_dir->last_sched_id--;
	if (--process_dir->num_schedulers == 0)
		remove_process_proc_dir(process_dir);
fail_process_dir:
	mutex_unlock(&proc_directory_lock);
fail_copy_from_user:
	kfree(scheduler->completion_list);
fail_completion_list_alloc:
	kfree(scheduler);
fail_scheduler_alloc:
	return ret;
}

int __scheduler_thread_terminated(pid_t scheduler_id, pid_t process_id)
{
	struct scheduler_thread *scheduler;
	struct process_proc_dir *process_dir;
	char index[12];
	int i;

	scheduler = rhashtable_lookup_fast(&scheduler_threads, &scheduler_id,
																		 scheduler_thread_table_params);
	if (scheduler == NULL)
		return -ENOENT;

	rhashtable_remove_fast(&scheduler_threads, &scheduler->node,
												 scheduler_thread_table_params);

	for (i = 0; i < scheduler->num_workers; i++) {
		sprintf(index, "%d", i);
		remove_proc_entry(index, scheduler->workers_dir);
	}
	proc_remove(scheduler->workers_dir);
	remove_proc_entry("info", scheduler->dir);

	mutex_lock(&proc_directory_lock);
	proc_remove(scheduler->dir);
	process_dir = rhashtable_lookup_fast(&proc_directories, &process_id,
																			 proc_directiory_table_params);
	if (--process_dir->num_schedulers == 0)
		remove_process_proc_dir(process_dir);
	mutex_unlock(&proc_directory_lock);

	kfree(scheduler->completion_list);
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
				spin_lock(&worker->lock);
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
				spin_unlock(&worker->lock);
			}

			up_read(&worker_lock);
		}

		if (found == 0) {
			/* all workers terminated */
			kfree(scheduler->dequeued_items);
			break;
		}

		if (fatal_signal_pending(current)) {
			kfree(scheduler->dequeued_items);
			return -EINTR;
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

int __execute_ums_thread(pid_t sched_id, pid_t worker_id, const cpumask_t *cpu)
{
	struct worker_thread *worker;
	struct scheduler_thread *scheduler;
	struct task_struct *pcb;

	scheduler = rhashtable_lookup_fast(&scheduler_threads, &sched_id,
																		 scheduler_thread_table_params);
	if (scheduler == NULL)
		return -ENOENT;

	down_read(&worker_lock);

	worker = rhashtable_lookup_fast(&worker_threads, &worker_id,
																	worker_thread_table_params);
	if (worker == NULL) {
		up_read(&worker_lock);
		return -ENOENT;
	}

	printk(KERN_DEBUG MODULE_NAME_LOG "scheduler:%d executing worker:%d\n",
				 sched_id, worker_id);

	spin_lock(&worker->lock);
	worker->state = UMS_RUNNING;
	worker->switch_num++;
	pcb = pid_task(find_vpid(worker->id), PIDTYPE_PID);
	spin_unlock(&worker->lock);

	up_read(&worker_lock);

	spin_lock(&scheduler->lock);
	scheduler->worker = worker_id;
	scheduler->switch_num++;
	spin_unlock(&scheduler->lock);

	set_current_state(TASK_KILLABLE);
	set_cpus_allowed_ptr(pcb, cpu);
	wake_up_process(pcb);
	schedule();

	/* after context switch */
	printk(KERN_DEBUG MODULE_NAME_LOG "Back from switch:%d\n", sched_id);

	spin_lock(&scheduler->lock);
	scheduler->worker = -1;
	spin_unlock(&scheduler->lock);

	return SUCCESS;
}

int __ums_thread_yield(pid_t id)
{
	struct worker_thread *worker;
	struct task_struct *pcb;

	down_read(&worker_lock);
	worker =
		rhashtable_lookup_fast(&worker_threads, &id, worker_thread_table_params);

	if (worker == NULL)
		return -ENOENT;

	spin_lock(&worker->lock);
	pcb = pid_task(find_vpid(worker->scheduler), PIDTYPE_PID);
	worker->state = UMS_YIELD;
	worker->scheduler = -1;

	set_current_state(TASK_KILLABLE);

	spin_unlock(&worker->lock);
	up_read(&worker_lock);

	printk(KERN_DEBUG MODULE_NAME_LOG "worker:%d waking scheduler:%d\n", id,
				 pcb->pid);

	wake_up_process(pcb);
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

		return __register_worker_thread(current->pid, (pid_t *)data);

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

		return __register_scheduler_thread(current->pid, current->tgid, &list);

	case SCHEDULER_THREAD_TERMINATED:
		printk(KERN_DEBUG MODULE_NAME_LOG "SCHEDULER_THREAD_TERMINATED pid:%d\n",
					 current->pid);

		return __scheduler_thread_terminated(current->pid, current->tgid);

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

		return __execute_ums_thread(current->pid, pid, current->cpus_ptr);

	case UMS_THREAD_YIELD:
		printk(KERN_DEBUG MODULE_NAME_LOG "UMS_THREAD_YIELD pid:%d\n",
					 current->pid);

		return __ums_thread_yield(current->pid);
	}

	return -EINVAL;
}