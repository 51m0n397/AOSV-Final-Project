#ifndef UMS_MODULE
#define UMS_MODULE

#define DEVICE_NAME "ums_device"
#define SUCCESS 0

int init_module(void);
void cleanup_module(void);
static long device_ioctl(struct file *file, unsigned int request,
			 unsigned long data);

#endif