#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

#include "ums_module.h"

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
	return SUCCESS;
}