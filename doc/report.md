# AOSV Final Project Report
_A.Y. 2020/2021_

Author: Simone Bartolini (1752197) 

# Introduction

This project is an implementation of User Mode Scheduling for the Linux Kernel version 5.11.2. The feature is implemented as a kernel module that defines a virtual device to which userspace applications can make requests using the ioctl system call. The file [ums_interface.h](../src/kernel/ums_interface.h) defines the ioctl request numbers.
The library [ums.h](../src/library/ums.h) defines wrapper functions around the ioctl requests and additional userspace utility functions to ease developement.

Users of the library are supposed to:
- create the completion lists for the schedulers using the function create_ums_completion_list();
- create worker threads using the function create_ums_thread();
- enqueue the worker threads inside the completion lists using the function enqueue_ums_completion_list_item();
- convert a standard pthread into a scheduler thread using the function enter_ums_scheduling_mode() that will take in input the completion list of worker threads to be scheduled and an entry point function that will be responsible for choosing the next worker thread to execute;
- inside the entry point function:
  - retrieve the list of the worker threads currently ready to be scheduled using the function dequeue_ums_completion_list_items();
  - iterate the list of ready worker threads using the function get_next_ums_list_item();
  - execute a worker thread using the function execute_ums_thread();
- inside a worker thread, yield the control of the CPU to the scheduler using the function ums_thread_yield();
- once all workers and schedulers have terminated, free the memory occupied by the completion lists using delete_ums_completion_list();

Additionally, the library defines the functions create_ready_queue(), delete_ready_queue(), enqueue_ready_queue() and dequeue_ready_queue() that can be used by a UMS scheduler to define a FIFO queue in which to put the ready worker threads dequeued by dequeue_ums_completion_list_items().
Check the file [main.c](../src/user/main.c) for an example and [refman.pdf](refman.pdf) for a more detailed description of the APIs.

# Noteworthy design decisions

- The function create_ums_thread() takes in input the start routine of the thread, the arguments of the start routine and a pointer to a ums_t variable. 
The function will call pthread_create() to create a thread that will first issue a request to the UMS kernel module in order to register the thread as a UMS worker end then wait to be scheduled before calling the start routine passed in input. ums_t is a struct containing both the pthread ID, which will be set by the call to pthread_create() and the Linux kernel PID of the thread, that will be set by the request to the UMS module. The reason for using both is that they are not the same, and the pthread ID is needed for joining, detaching or doing any other operation using the pthread library, while the PID is needed in the UMS module as it is the identifier internally used by the system.

- The scheduling is achieved by putting the worker threads on killable sleep as soon as they are created or when they yield and waking them up when executed by a scheduler. Note that the use of killable sleep is to ensure that the threads are not wakened by signals unless they are fatal. The killable sleep is also used to make the schedulers wait for the workers to yield or terminate. Note that the real scheduling is still done by the system scheduler, which does not ensure that the worker is immediately scheduled as soon as the wake_up_process() function is called. To minimize this delay the function yield_to() is used to suggest the system scheduler pick our thread as the next task to be scheduled.

- In the kernel module, the data structures representing the worker and scheduler threads are kept inside resizable hash tables, that change size according to the occupancy of the buckets. This ensures that the lookup cost is always constant, which is critical to minimize the time needed for a context switch.

- To allow multiple schedulers to share the same completion list and multiple completion list to share worker threads the function dequeue_ums_completion_list_items() will scan the completion list to find worker threads ready to be executed and assign them to the calling scheduler. Subsequent calls to the same function by another scheduler will not dequeue threads that are already assigned, even if they are still idle. A worker thread will be available again to be dequeued only when it becomes idle again after being executed. A dequeue_ums_completion_list_items() cannot find any available worker the calling scheduler will be kept waiting until either a thread becomes available or all threads in the completion list terminate.

- Inside the UMS library, the communication with the kernel module is done through the wrapper function ums_syscall() that, the first time it is called, will open the file descriptor for the virtual device and register a function to close it when the program exits, and then will use ioctl() to send requests to the module. Inside the module, the device_open() function is responsible for initializing the data structures relative to the calling process while the device_release() cleans all data used. This ensures that even if the program does not execute the close() function due to a crash, everything is still cleaned as the OS will still call device_release() for every open file descriptor upon termination.

- A user of the library can bind a scheduler to a specific CPU by setting the affinity. When a worker thread is executed its CPU mask is set to be equal to the one of the scheduler, ensuring that it will run on the same CPU as the scheduler.

# Results
The test program was executed in a VM with 6 CPU logical cores and 8 GB of ram on top of a 2012 MacBook Pro with an i7 3720QM with base and boost clocks of 2.6 GHz and 3.6 GHz respectively. The code defines 6 scheduler threads (one per core), 12 worker threads, and two completion lists. The first completion list contains all the workers while the second only the odd ones. Similarly, even schedulers use the first completion list while odd schedulers the second. This allows testing both schedulers sharing completion lists and completion lists sharing workers. Each worker yields 100 times. 
The average switch time was 124894 nanoseconds, with a median of  6326 nanoseconds, a minimum of 3197 nanoseconds, a maximum of 29454999 nanoseconds and a standard deviation of 1348439. 
Testing following the procedure detailed [here](https://eli.thegreenplace.net/2018/measuring-context-switching-and-memory-overheads-for-linux-threads/#id7) I get an average system context switch time of 6426 nanoseconds on the same VM. This means that the overhead of my module varies a lot from nearly zero to very significant. My hypothesis is that this is due to two factors:
- waiting to acquire the lock to access the worker and scheduler structs;
- the OS scheduler not always scheduling immediately the worker;

The delay introduced by both can vary significantly, which explains the high deviation.

# Conclusions
The decision to implement the functionality as a kernel module is the main limiting factor. While it is definitely easier to develop a module than to patch the kernel, it severely restricts what can be done. An example is the impossibility to directly call switch_to() to switch from a scheduler to a worker. The use of yield_to() does not ensure that the worker will be immediately executed, the OS scheduler might pick another thread from another process to be executed before. It is then safe to assume that better performance results could be achieved by changing directly the kernel source code.

# References