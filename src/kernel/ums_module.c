#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "ums_interface.h"

/* Used for logging */
#define MODULE_NAME_LOG "UMS: "

/* Used for time converions */
#define NSEC_PER_MIN	(60 * NSEC_PER_SEC)
#define NSEC_PER_HOUR	(60 * NSEC_PER_MIN)
#define NSEC_PER_DAY	(24 * NSEC_PER_HOUR)

/* Used for the return value of functions */
#define SUCCESS		0

/* The state of a worker thread */
#define UMS_NEW		0
#define UMS_RUNNING	1
#define UMS_YIELD	2

/* Used for converting integers to string */
#define INT_DECIMAL_STRING_SIZE(int_type)                                      \
	((8 * sizeof(int_type) - 1) * 10 / 33 + 3)

/**
 * worker_thread - a UMS worker thread.
 * @id: the PID of the thread.
 * @scheduler: the scheduler that is running the worker thread.
 * @state: the state of the worker thread.
 * @num_switch: the number of switches.
 * @running_time: the total running time of the thread.
 * @last_switch: the time the last switch occurred.
 */
struct worker_thread {
	pid_t			id;
	struct rhash_head	node;
	spinlock_t		lock;
	pid_t			scheduler;
	int			state;
	int			num_switch;
	ktime_t			running_time;
	ktime_t			last_switch;
};

/**
 * scheduler_thread - a UMS scheduler thread.
 * @id: the PID of the thread.
 * @completion_list: array of PIDs of the workers the scheduler needs to
 *                   execute.
 * @num_workers: the number of elements in @completion_list.
 * @dequeued_items: array of PIDs of the workers that are currently ready
 *                  to be runned.
 * @num_dequeued_items: the number of elements in @dequeued_items.
 * @dir: the proc directory of the scheduler thread.
 * @workers_dir: the workers directory inside @dir.
 * @worker: the worker that is currently scheduled by the scheduler.
 * @num_switch: the number of switches.
 * @last_switch_time: the time needed for the last switch.
 * @last_switch_start: the time the last switch started.
 */
struct scheduler_thread {
	pid_t			id;
	struct rhash_head	node;
	spinlock_t		lock;
	pid_t			*completion_list;
	int			num_workers;
	pid_t			*dequeued_items;
	int			num_dequeued_items;
	struct proc_dir_entry	*dir;
	struct proc_dir_entry	*workers_dir;
	pid_t			worker;
	int			num_switch;
	ktime_t			last_switch_time;
	ktime_t			last_switch_start;
};

/**
 * process_proc_dir - the proc dir of a process.
 * @id: the PID of the process.
 * @num_schedulers: the number of currently active schedulers in the process.
 * @last_sched_id: the id of the last scheduler created in the process.
 * @pid_dir: the process proc dir.
 * @schedulers_dir: the schedulers dir inside @pid_dir.
 */
struct process_proc_dir {
	pid_t			id;
	struct rhash_head	node;
	int			num_schedulers;
	int			last_sched_id;
	struct proc_dir_entry	*pid_dir;
	struct proc_dir_entry	*schedulers_dir;
};

/* Parameters for the device */
static long device_ioctl(struct file *file, unsigned int request,
			 unsigned long data);
static struct file_operations fops = { 
	.unlocked_ioctl = device_ioctl,
};

static struct miscdevice mdev = { 
	.minor	= 0,
	.name	= DEVICE_NAME,
	.mode	= S_IALLUGO,
	.fops	= &fops,
};

/* Parameters for the tables */
const static struct rhashtable_params worker_thread_table_params = {
	.key_len	= sizeof(pid_t),
	.key_offset	= offsetof(struct worker_thread, id),
	.head_offset	= offsetof(struct worker_thread, node),
};

const static struct rhashtable_params scheduler_thread_table_params = {
	.key_len	= sizeof(pid_t),
	.key_offset	= offsetof(struct scheduler_thread, id),
	.head_offset	= offsetof(struct scheduler_thread, node),
};

const static struct rhashtable_params proc_directiory_table_params = {
	.key_len	= sizeof(pid_t),
	.key_offset	= offsetof(struct process_proc_dir, id),
	.head_offset	= offsetof(struct process_proc_dir, node),
};

struct rhashtable worker_threads;    /* Table containing the worker threads */
struct rhashtable scheduler_threads; /* Table containing the scheduler threads */
struct rhashtable proc_directories;  /* Table containing the proc directories */

/* Semaphore for accessing the worker_threads table */
static DECLARE_RWSEM(worker_lock);
/* Mutex for accessing the proc_directories table */
static DEFINE_MUTEX(proc_directory_lock);

static struct proc_dir_entry *ums_dir; /* The ums dir inside proc */

/* Parameters for the proc files */
static int scheduler_open(struct inode *inode, struct file *file);
static struct proc_ops scheduler_fops = { 
	.proc_open	= scheduler_open,
	.proc_read	= seq_read,
	.proc_release	= single_release,
};

static int worker_open(struct inode *inode, struct file *file);
static struct proc_ops worker_fops = {
	.proc_open	= worker_open,
	.proc_read	= seq_read,
	.proc_release	= single_release,
};

int init_module(void)
{
	int ret;
	printk(KERN_DEBUG MODULE_NAME_LOG "Initializing module\n");

	ret = misc_register(&mdev);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG
		       "Registering misc device failed\n");
		goto fail_mdev;
	}

	ret = rhashtable_init(&worker_threads, &worker_thread_table_params);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG
		       "Creating worker thread table failed\n");
		goto fail_worker_threads;
	}

	ret = rhashtable_init(&scheduler_threads,
			      &scheduler_thread_table_params);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG
		       "Creating scheduler thread table failed\n");
		goto fail_scheduler_threads;
	}

	ret = rhashtable_init(&proc_directories, &proc_directiory_table_params);
	if (ret < 0) {
		printk(KERN_ALERT MODULE_NAME_LOG
		       "Creating proc directory table failed\n");
		goto fail_proc_directories;
	}

	ums_dir = proc_mkdir("ums", NULL);
	if (!ums_dir) {
		printk(KERN_ALERT MODULE_NAME_LOG
		       "Creating ums proc folder failed\n");
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

/* Generates the proc file for a scheduler */
static int scheduler_show(struct seq_file *m, void *v)
{
	int i;
	s64 time;
	struct scheduler_thread *scheduler = m->private;

	spin_lock(&scheduler->lock);

	seq_printf(m, "Pid:\t %d\n", scheduler->id);
	seq_printf(m, "Completion list:\n");
	for (i = 0; i < scheduler->num_workers; i++) {
		seq_printf(m, "\t %d)\t %d\n", i,
			   scheduler->completion_list[i]);
	}
	if (scheduler->worker == -1)
		seq_printf(m, "State:\t Idle\n");
	else {
		seq_printf(m, "State:\t Running\n");
		seq_printf(m, "Worker:\t %d\n", scheduler->worker);
	}
	seq_printf(m, "Number of switches:\t %d\n", scheduler->num_switch);
	time = ktime_to_ns(scheduler->last_switch_time);
	if (time > 0)
		seq_printf(m, "Last switch time:\t %lld ns\n", time);

	spin_unlock(&scheduler->lock);

	return SUCCESS;
}

static int scheduler_open(struct inode *inode, struct file *file)
{
	return single_open(file, scheduler_show, PDE_DATA(inode));
}

/* Generates the proc file for a worker */
static int worker_show(struct seq_file *m, void *v)
{
	struct worker_thread *worker;
	int *id = m->private;
	ktime_t time;
	s64 day, hour, min, sec, ms, us;

	seq_printf(m, "Pid:\t %d\n", *id);

	down_read(&worker_lock);

	/* Retrieving the worker_thread struct from the worker_threads table */
	worker = rhashtable_lookup_fast(&worker_threads, id,
					worker_thread_table_params);
	if (worker != NULL) {
		spin_lock(&worker->lock);

		if (worker->state == UMS_RUNNING) {
			seq_printf(m, "State:\t Running\n");
			seq_printf(m, "Scheduler:\t %d\n", worker->scheduler);
			time = ktime_add(worker->running_time,
					 ktime_sub(ktime_get(),
						   worker->last_switch));
		} else {
			seq_printf(m, "State:\t Idle\n");
			time = worker->running_time;
		}
		seq_printf(m, "Number of switches:\t %d\n", worker->num_switch);

		day = ktime_divns(time, NSEC_PER_DAY);
		time = time - day * NSEC_PER_DAY;
		hour = ktime_divns(time, NSEC_PER_HOUR);
		time = time - hour * NSEC_PER_HOUR;
		min = ktime_divns(time, NSEC_PER_MIN);
		time = time - min * NSEC_PER_MIN;
		sec = ktime_divns(time, NSEC_PER_SEC);
		time = time - sec * NSEC_PER_SEC;
		ms = ktime_divns(time, NSEC_PER_MSEC);
		time = time - ms * NSEC_PER_MSEC;
		us = ktime_divns(time, NSEC_PER_USEC);
		time = time - us * NSEC_PER_USEC;

		seq_printf(m,
			   "Running time:\t "
			   "%lld days, %lld hours, %lld minutes, %lld seconds, "
			   "%lld ms, %lld us, %lld ns\n",
			   day, hour, min, sec, ms, us, time);

		spin_unlock(&worker->lock);
	} else {
		/**
		 * Once a worker terminates it frees its relative worker_thread
		 * struct so we can't print all its statistics.
		 */
		seq_printf(m, "State:\t Terminated\n");
	}

	up_read(&worker_lock);

	return SUCCESS;
}

static int worker_open(struct inode *inode, struct file *file)
{
	return single_open(file, worker_show, PDE_DATA(inode));
}

/**
 * create_process_proc_dir - creates a proc directory for the given process.
 * @pid: the PID of the process.
 *
 * Since the relative process_proc_dir struct is inserted in the
 * proc_directories table, it must be called while holding the
 * proc_directory_lock lock.
 *
 * Returns a pointer to a process_proc_dir struct containing the info about
 * the created directory on success, an error code on failure:
 *  -ENOMEM: not enough memory
 *  -EEXIST: directory already created
 */
struct process_proc_dir *create_process_proc_dir(pid_t pid)
{
	int ret;
	char id[INT_DECIMAL_STRING_SIZE(pid_t)];
	struct process_proc_dir *dir, *err;

	/* Allocating the process_proc_dir struct */
	dir = kzalloc(sizeof(struct process_proc_dir), GFP_KERNEL);
	if (dir == NULL) {
		err = ERR_PTR(-ENOMEM);
		goto fail_alloc;
	}

	dir->id = pid;
	dir->num_schedulers = 0;
	dir->last_sched_id = 0;

	/* Creating the process proc dir */
	sprintf(id, "%d", pid);
	dir->pid_dir = proc_mkdir(id, ums_dir);
	if (dir->pid_dir == NULL) {
		err = ERR_PTR(-ENOMEM);
		goto fail_mk_pid_dir;
	}

	/* Creating the schedulers dir */
	dir->schedulers_dir = proc_mkdir("schedulers", dir->pid_dir);
	if (dir->schedulers_dir == NULL) {
		err = ERR_PTR(-ENOMEM);
		goto fail_mk_schedulers_dir;
	}

	/* Inserting the struct in the proc_directories table */
	ret = rhashtable_lookup_insert_fast(&proc_directories, &dir->node,
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

/**
 * remove_process_proc_dir - emoves the proc directory passed in input.
 * @dir: a pointer to a process_proc_dir struct containing the info about
 *       the directory to be removed.
 *
 * Since the relative struct process_proc_dir is also removed from the
 * proc_directories table, it must be called while holding the
 * proc_directory_lock lock.
 */
void remove_process_proc_dir(struct process_proc_dir *dir)
{
	rhashtable_remove_fast(&proc_directories, &dir->node,
			       proc_directiory_table_params);
	proc_remove(dir->schedulers_dir);
	proc_remove(dir->pid_dir);
	kfree(dir);
}

int __register_worker_thread(pid_t worker_id, pid_t *userspace_worker_id)
{
	struct worker_thread *worker;
	struct scheduler_thread *scheduler;
	int ret;
	ktime_t now;

	/* Allocating the worker_thread struct */
	worker = kzalloc(sizeof(struct worker_thread), GFP_KERNEL);
	if (worker == NULL) {
		ret = -ENOMEM;
		goto fail_alloc;
	}

	worker->id = worker_id;
	worker->scheduler = -1;
	worker->state = UMS_NEW;
	worker->num_switch = 0;
	worker->running_time = ktime_set(0, 0);
	spin_lock_init(&worker->lock);

	down_write(&worker_lock);

	/* Inserting the struct in the proc_directories table */
	ret = rhashtable_lookup_insert_fast(&worker_threads, &worker->node,
					    worker_thread_table_params);
	if (ret < 0)
		goto fail_insert;

	/* Copying the worker pid to userspace */
	if (copy_to_user(userspace_worker_id, &worker_id, sizeof(pid_t))) {
		ret = -EFAULT;
		goto fail_copy;
	}

	up_write(&worker_lock);

	/* Going to sleep */
	set_current_state(TASK_KILLABLE);
	schedule();

	/* After context switch */
	now = ktime_get();

	/* Retrieving scheduler_thread struct from the scheduler_threads table */
	scheduler =
		rhashtable_lookup_fast(&scheduler_threads, &worker->scheduler,
				       scheduler_thread_table_params);

	/* Updating scheduler struct */
	if (scheduler != NULL) {
		spin_lock(&scheduler->lock);
		scheduler->last_switch_time =
			ktime_sub(now, scheduler->last_switch_start);
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "Switched to worker %d in %lld ns\n",
		       worker_id, ktime_to_ns(scheduler->last_switch_time));
		spin_unlock(&scheduler->lock);
	}

	/* Updating worker struct */
	spin_lock(&worker->lock);
	worker->last_switch = ktime_get();
	spin_unlock(&worker->lock);

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

int __worker_thread_terminated(pid_t worker_id)
{
	struct worker_thread *worker;
	struct task_struct *pcb;

	down_write(&worker_lock);

	/* Retrieving worker_tread struct from the worker_threads table */
	worker = rhashtable_lookup_fast(&worker_threads, &worker_id,
					worker_thread_table_params);
	if (worker == NULL) {
		up_write(&worker_lock);
		return -ESRCH;
	}

	/* Retrieving the task_struct of the scheduler */
	pcb = pid_task(find_vpid(worker->scheduler), PIDTYPE_PID);

	/**
	 * Removing the worker_thread struct from the worker_threads table and
	 * freeing it
	 */
	rhashtable_remove_fast(&worker_threads, &worker->node,
			       worker_thread_table_params);
	kfree(worker);

	up_write(&worker_lock);

	printk(KERN_DEBUG MODULE_NAME_LOG "worker:%d waking scheduler:%d\n",
	       worker_id, pcb->pid);

	/* Waking the scheduler */
	wake_up_process(pcb);
	if (yield_to(pcb, true) == 0)
		schedule();

	return SUCCESS;
}

int __register_scheduler_thread(pid_t sched_id, pid_t process_id,
				struct thread_list *completion_list)
{
	struct scheduler_thread *scheduler;
	struct process_proc_dir *process_dir;
	char index[INT_DECIMAL_STRING_SIZE(int)];
	int ret, i;

	/* Allocating scheduler_thread struct */
	scheduler = kzalloc(sizeof(struct scheduler_thread), GFP_KERNEL);
	if (scheduler == NULL) {
		ret = -ENOMEM;
		goto fail_scheduler_alloc;
	}

	scheduler->id = sched_id;
	scheduler->dequeued_items = NULL;
	scheduler->num_dequeued_items = 0;
	scheduler->num_workers = completion_list->size;
	scheduler->worker = -1;
	scheduler->num_switch = 0;
	scheduler->last_switch_time = ktime_set(0, 0);
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
		       sched_id, scheduler->completion_list[i]);
	}

	/*
	 * Creating proc directory for the scheduler.
	 * We first check if the process proc directory already exists,
	 * otherwise we create it.
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
		if (!proc_create_data(index, 0, scheduler->workers_dir,
				      &worker_fops,
				      &scheduler->completion_list[i])) {
			ret = -ENOMEM;
			goto fail_worker_info;
		}
	}

	/* Inserting the struct in the scheduler_threads table */
	ret = rhashtable_lookup_insert_fast(&scheduler_threads,
					    &scheduler->node,
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

int __scheduler_thread_terminated(pid_t sched_id, pid_t process_id)
{
	struct scheduler_thread *scheduler;
	struct process_proc_dir *process_dir;
	char index[INT_DECIMAL_STRING_SIZE(int)];
	int i;

	/* Retrieving scheduler_thread struct from the scheduler_threads table */
	scheduler = rhashtable_lookup_fast(&scheduler_threads, &sched_id,
					   scheduler_thread_table_params);
	if (scheduler == NULL)
		return -ESRCH;

	/* Removing the scheduler_thread struct from the scheduler_threads table */
	rhashtable_remove_fast(&scheduler_threads, &scheduler->node,
			       scheduler_thread_table_params);

	/* Removing the workers proc files and directory */
	for (i = 0; i < scheduler->num_workers; i++) {
		sprintf(index, "%d", i);
		remove_proc_entry(index, scheduler->workers_dir);
	}
	proc_remove(scheduler->workers_dir);

	/* Removing the scheduler info file */
	remove_proc_entry("info", scheduler->dir);

	mutex_lock(&proc_directory_lock);

	/* Removing the scheduler proc directory */
	proc_remove(scheduler->dir);

	/* Retrieving process_proc_dir struct from the proc_directories table */
	process_dir = rhashtable_lookup_fast(&proc_directories, &process_id,
					     proc_directiory_table_params);

	/**
	 * If this is the last scheduler of this process we can remove the
	 * process proc dir
	 */
	if (--process_dir->num_schedulers == 0)
		remove_process_proc_dir(process_dir);

	mutex_unlock(&proc_directory_lock);

	/* Freeing the completion list and the scheduler struct */
	kfree(scheduler->completion_list);
	kfree(scheduler);

	return SUCCESS;
}

int __dequeue_ums_completion_list_items(pid_t sched_id)
{
	struct scheduler_thread *scheduler;
	struct worker_thread *worker;
	int i, found;

	/* Retrieving scheduler_thread struct from the scheduler_threads table */
	scheduler = rhashtable_lookup_fast(&scheduler_threads, &sched_id,
					   scheduler_thread_table_params);
	if (scheduler == NULL)
		return -ESRCH;

	/**
	 * A DEQUEUE_UMS_COMPLETION_LIST_ITEMS syscall must be followed by a
	 * GET_DEQUEUED_ITEMS syscall to retrieve the dequeued items.
	 * If scheduler->num_dequeued_items is greater than zero it means that
	 * the user is calling again DEQUEUE_UMS_COMPLETION_LIST_ITEMS without
	 * having called GET_DEQUEUED_ITEMS first, which is not permitted.
	 */
	if (scheduler->num_dequeued_items > 0)
		return -EPERM;

	/**
	 * Allocating array where to put dequeued workers. The array has size
	 * equal to scheduler->num_workers since at most all workers in the
	 * completion list are ready to be dequeued.
	 */
	scheduler->dequeued_items =
		kcalloc(scheduler->num_workers, sizeof(pid_t), GFP_KERNEL);
	if (scheduler->dequeued_items == NULL)
		return -ENOMEM;

	/**
	 * Loop until we find at least a ready worker, or all worker have
	 * terminated, or we are interrupted by a fatal signal.
	 */
	while (scheduler->num_dequeued_items == 0) {
		found = 0;
		for (i = 0; i < scheduler->num_workers; i++) {
			down_read(&worker_lock);

			/**
			 * Retrieving worker_thread struct from the
			 * worker_threads table 
			 */
			worker = rhashtable_lookup_fast(
				&worker_threads, &scheduler->completion_list[i],
				worker_thread_table_params);

			/* If the worker is not in the table it has terminated */
			if (worker != NULL) {
				spin_lock(&worker->lock);

				found++;

				/**
				 * If worker->scheduler = -1 it is not assigned
				 * to a scheduler 
				 */
				if (worker->scheduler == -1) {
					/**
					 * Assiging the worker to this scheduler
					 */
					worker->scheduler = sched_id;
					scheduler->dequeued_items
						[scheduler->num_dequeued_items++] =
						worker->id;

					printk(KERN_DEBUG MODULE_NAME_LOG
					       "scheduler:%d dequeued worker:%d\n",
					       sched_id, worker->id);
				}

				spin_unlock(&worker->lock);
			}

			up_read(&worker_lock);
		}

		if (found == 0) {
			/* All workers terminated */
			kfree(scheduler->dequeued_items);
			break;
		}

		if (fatal_signal_pending(current)) {
			/* Interrupted by fatal signal */
			kfree(scheduler->dequeued_items);
			return -EINTR;
		}
	}

	/* Returning the number of dequeued items */
	return scheduler->num_dequeued_items;
}

int __get_dequeued_items(pid_t sched_id, pid_t *userspace_list)
{
	struct scheduler_thread *scheduler;

	/* Retrieving scheduler_thread struct from the scheduler_threads table */
	scheduler = rhashtable_lookup_fast(&scheduler_threads, &sched_id,
					   scheduler_thread_table_params);
	if (scheduler == NULL)
		return -ESRCH;

	/* Copying the list of dequeued items to userspace */
	if (copy_to_user(userspace_list, scheduler->dequeued_items,
			 sizeof(pid_t) * scheduler->num_dequeued_items))
		return -EFAULT;

	/* Freeing the list of dequeued items */
	kfree(scheduler->dequeued_items);
	scheduler->num_dequeued_items = 0;

	return SUCCESS;
}

int __execute_ums_thread(pid_t sched_id, pid_t worker_id, const cpumask_t *cpu)
{
	struct worker_thread *worker;
	struct scheduler_thread *scheduler;
	struct task_struct *pcb;
	ktime_t now = ktime_get();

	/* Retrieving scheduler_thread struct from the scheduler_threads table */
	scheduler = rhashtable_lookup_fast(&scheduler_threads, &sched_id,
					   scheduler_thread_table_params);
	if (scheduler == NULL)
		return -ESRCH;

	down_read(&worker_lock);

	/* Retrieving worker_thread struct from the worker_threads table */
	worker = rhashtable_lookup_fast(&worker_threads, &worker_id,
					worker_thread_table_params);
	if (worker == NULL) {
		up_read(&worker_lock);
		return -ESRCH;
	}

	printk(KERN_DEBUG MODULE_NAME_LOG "scheduler:%d executing worker:%d\n",
	       sched_id, worker_id);

	/* Updating worker struct and retrieving worker task_struct */
	spin_lock(&worker->lock);
	worker->state = UMS_RUNNING;
	worker->num_switch++;
	pcb = pid_task(find_vpid(worker->id), PIDTYPE_PID);
	spin_unlock(&worker->lock);

	up_read(&worker_lock);

	/* Updating Scheduler struct */
	spin_lock(&scheduler->lock);
	scheduler->worker = worker_id;
	scheduler->num_switch++;
	scheduler->last_switch_start = now;
	spin_unlock(&scheduler->lock);

	/**
	 * Waking worker on the same cpu as the scheduler and putting the
	 * scheduler to sleep.
	 */
	set_current_state(TASK_KILLABLE);
	set_cpus_allowed_ptr(pcb, cpu);
	wake_up_process(pcb);
	if (yield_to(pcb, true) == 0)
		schedule();

	/* After context switch */
	printk(KERN_DEBUG MODULE_NAME_LOG "Scheduler %d back from switch\n",
	       sched_id);

	/* Updating Scheduler struct */
	spin_lock(&scheduler->lock);
	scheduler->worker = -1;
	spin_unlock(&scheduler->lock);

	return SUCCESS;
}

int __ums_thread_yield(pid_t id)
{
	struct worker_thread *worker;
	struct scheduler_thread *scheduler;
	struct task_struct *pcb;
	ktime_t now;

	down_read(&worker_lock);

	/* Retrieving worker_thread struct from the worker_threads table */
	worker = rhashtable_lookup_fast(&worker_threads, &id,
					worker_thread_table_params);
	if (worker == NULL)
		return -ESRCH;

	spin_lock(&worker->lock);

	/* Updating worker struct and retrieving scheduler task_struct */
	worker->running_time =
		ktime_add(worker->running_time,
			  ktime_sub(ktime_get(), worker->last_switch));
	pcb = pid_task(find_vpid(worker->scheduler), PIDTYPE_PID);
	worker->state = UMS_YIELD;
	worker->scheduler = -1;

	set_current_state(TASK_KILLABLE);

	spin_unlock(&worker->lock);

	up_read(&worker_lock);

	printk(KERN_DEBUG MODULE_NAME_LOG "worker:%d waking scheduler:%d\n", id,
	       pcb->pid);

	/* Waking scheduler and putting worker to sleep */
	wake_up_process(pcb);
	if (yield_to(pcb, true) == 0)
		schedule();

	/* After context switch */
	now = ktime_get();

	/* Retrieving scheduler_thread struct from the scheduler_threads table */
	scheduler =
		rhashtable_lookup_fast(&scheduler_threads, &worker->scheduler,
				       scheduler_thread_table_params);

	/* Updating scheduler struct */
	if (scheduler != NULL) {
		spin_lock(&scheduler->lock);
		scheduler->last_switch_time =
			ktime_sub(now, scheduler->last_switch_start);
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "Switched to worker %d in %lld ns\n",
		       id, ktime_to_ns(scheduler->last_switch_time));
		spin_unlock(&scheduler->lock);
	}

	/* Updating worker struct */
	spin_lock(&worker->lock);
	worker->last_switch = ktime_get();
	spin_unlock(&worker->lock);

	return SUCCESS;
}

static long device_ioctl(struct file *file, unsigned int request,
			 unsigned long data)
{
	pid_t pid;
	struct thread_list list;

	switch (request) {
	case REGISTER_WORKER_THREAD:
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "REGISTER_WORKER_THREAD pid:%d\n",
		       current->pid);

		return __register_worker_thread(current->pid, (pid_t *)data);

	case WORKER_THREAD_TERMINATED:
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "WORKER_THREAD_TERMINATED pid:%d\n",
		       current->pid);

		return __worker_thread_terminated(current->pid);

	case REGISTER_SCHEDULER_THREAD:
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "REGISTER_SCHEDULER_THREAD pid:%d\n",
		       current->pid);

		if (copy_from_user(&list, (struct thread_list *)data,
				   sizeof(struct thread_list)))
			return -EFAULT;

		return __register_scheduler_thread(current->pid, current->tgid,
						   &list);

	case SCHEDULER_THREAD_TERMINATED:
		printk(KERN_DEBUG MODULE_NAME_LOG
		       "SCHEDULER_THREAD_TERMINATED pid:%d\n",
		       current->pid);

		return __scheduler_thread_terminated(current->pid,
						     current->tgid);

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

		return __execute_ums_thread(current->pid, pid,
					    current->cpus_ptr);

	case UMS_THREAD_YIELD:
		printk(KERN_DEBUG MODULE_NAME_LOG "UMS_THREAD_YIELD pid:%d\n",
		       current->pid);

		return __ums_thread_yield(current->pid);
	}

	return -EINVAL;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Bartolini <bartolini.1752197@studenti.uniroma1.it>");
MODULE_DESCRIPTION("User Mode Scheduling module");
MODULE_VERSION("1.0.0");