#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include<linux/slab.h>                 //kmalloc()
#include<linux/uaccess.h>              //copy_to/from_user()
#include<linux/sysfs.h> 
#include<linux/kobject.h> 
#include <linux/err.h>
#include<linux/sched.h>
#include<linux/mutex.h>

 

//values to read
#define PID 		0
#define	STATIC_PRIO 	1
#define	COMM 		2
#define PPID		3
#define NVCSW		4
#define NUM_THREADS	5
#define NUM_FILES_OPEN	6
#define STACK_SIZE	7

#define DEVNAME "cs614_device"

static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;
static short mess_len;

static char *d_buf = NULL;

static DEFINE_MUTEX(cs614_mutex);
/*
** Function Prototypes
*/
static int      __init cs614_driver_init(void);
static void     __exit cs614_driver_exit(void);


static ssize_t traphook_read(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%s", "ha yes working");
}

static ssize_t traphook_write(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
        mutex_lock(&cs614_mutex);
        sprintf(d_buf, "%s", buf);
        printk(KERN_INFO "In write of sysfs\n");
        mess_len = strlen(d_buf);                 // store the length of the stored message
        printk(KERN_INFO "Received %zu characters from the user, mess_len is %hi\n", count, mess_len);
        return count;
}
static struct kobj_attribute traphook_attribute = __ATTR(cs614_value, 0660, traphook_read, traphook_write);
static struct attribute *traphook_attrs[] = {
        &traphook_attribute.attr,
        NULL,
};
static struct attribute_group traphook_attr_group = {
        .attrs = traphook_attrs,
        .name = "cs614_sysfs",
};

static int demo_open(struct inode *inode, struct file *file)
{
        atomic_inc(&device_opened);
        try_module_get(THIS_MODULE);
        printk(KERN_INFO "Device opened successfully\n");
        return 0;
}

static int demo_release(struct inode *inode, struct file *file)
{
        atomic_dec(&device_opened);
        module_put(THIS_MODULE);
        printk(KERN_INFO "Device closed successfully\n");
        return 0;
}

static ssize_t demo_read(struct file *filp,
                           char *ubuf,
                           size_t length,
                           loff_t * offset)
{
	
        struct task_struct *tsk = current;
        if(strcmp(d_buf, "0")==0)
        {
             int p = tsk->pid;
             printk(KERN_INFO "In read of driver pid is %d\n",p);
             mess_len=0;
             mutex_unlock(&cs614_mutex);
             return sprintf(ubuf,"%d",p);
                
        }
        else if(strcmp(d_buf, "1")==0)
        {
             int p = tsk->static_prio;
             printk(KERN_INFO "In read of driver statc prio is %d\n", p);
             mess_len=0;
             mutex_unlock(&cs614_mutex);
             return sprintf(ubuf,"%d",p);
                
        }
        else if(strcmp(d_buf, "2")==0)
        {
             printk(KERN_INFO "In read of driver comm is %s\n", tsk->comm);
             mess_len=0;
             mutex_unlock(&cs614_mutex);
             if(copy_to_user(ubuf, tsk->comm, strlen(tsk->comm)))
             {
                printk(KERN_INFO "copy to user failed\n");
                return -EINVAL;
             }
             return strlen(tsk->comm);
                
        }
        else if(strcmp(d_buf, "3")==0)
        {
             struct task_struct *tskp = tsk->real_parent;
             int p=tskp->pid;
             printk(KERN_INFO "In read of driver ppid is %d\n",p);
             mess_len=0;
             mutex_unlock(&cs614_mutex);
             return sprintf(ubuf,"%d",p);
                
        }
        else if(strcmp(d_buf, "4")==0)
        {
             unsigned long p = tsk->nvcsw;
             printk(KERN_INFO "In read of driver nvcsw is %lu\n", p);
             mess_len=0;
             mutex_unlock(&cs614_mutex);
             return sprintf(ubuf,"%lu",p);
                
        }
        else if(strcmp(d_buf, "5")==0)
        {
             int p = get_nr_threads(tsk);
             printk(KERN_INFO "In read of driver num threads is %d\n", p);
             mess_len=0;
             mutex_unlock(&cs614_mutex);
             return sprintf(ubuf,"%d",p);
                
        }
        else if(strcmp(d_buf, "6")==0)
        {
                struct fdtable *files_table;
                int p=0;
                files_table = files_fdtable(tsk->files);
                while(files_table->fd[p] != NULL) 
                { 
                        p++;
                }
                printk(KERN_INFO "In read of driver num open files is %d\n", p);
                mess_len=0;
                mutex_unlock(&cs614_mutex);
                return sprintf(ubuf,"%d",p);
        }
        else if(strcmp(d_buf, "7")==0)
        {
                struct task_struct *t = tsk;
                int p=0;
                do
                {
                        printk(KERN_INFO " this pid is %d\n", t->pid);
                        t = next_thread(t);
                        p++;
                }
                while(t!=tsk)
                mess_len=0;
                mutex_unlock(&cs614_mutex);
                return sprintf(ubuf, "%d", p);
        }
        else
        {
                printk(KERN_INFO "strcmp failed\n");
                mutex_unlock(&cs614_mutex);
                return -EINVAL;
        }
}

static ssize_t
demo_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
        if(copy_from_user(d_buf, buff, len))
                return -EINVAL;
        printk(KERN_INFO "In write of driver\n");
        mess_len = strlen(d_buf);                 // store the length of the stored message
        printk(KERN_INFO "Received %zu characters from the user, mess_len is %hi\n", len, mess_len);
        return len;
}

static struct file_operations fops = {
        .read = demo_read,
        .write = demo_write,
        .open = demo_open,
        .release = demo_release,
};

static char *demo_devnode(struct device *dev, umode_t *mode)
{
        if (mode && dev->devt == MKDEV(major, 0))
                *mode = 0666;
        return NULL;
}
/*
** Module Init function
*/
static int __init cs614_driver_init(void)
{
        int err;
        int ret;
        major = register_chrdev(0, DEVNAME, &fops);
        err = major;
        if (err < 0) {      
             printk(KERN_ALERT "Registering char device failed with %d\n", major);   
             goto error_regdev;
        }
        demo_class = class_create(THIS_MODULE, DEVNAME);
        err = PTR_ERR(demo_class);
        if (IS_ERR(demo_class))
                goto error_class;

        demo_class->devnode = demo_devnode;

        demo_device = device_create(demo_class, NULL,
                                        MKDEV(major, 0),
                                        NULL, DEVNAME);
        err = PTR_ERR(demo_device);
        if (IS_ERR(demo_device))
                goto error_device;
 
        d_buf = kzalloc(4096, GFP_KERNEL);
        printk(KERN_INFO "I was assigned major number %d. To talk to\n", major);                                                              
        atomic_set(&device_opened, 0);
        pr_info("Device Driver Insert...Done!!!\n");
        ret = sysfs_create_group (kernel_kobj, &traphook_attr_group);
        if(unlikely(ret))
                printk(KERN_INFO "demo: can't create sysfs\n");
        mutex_init(&cs614_mutex);
	return 0;

error_device:
         class_destroy(demo_class);
error_class:
        unregister_chrdev(major, DEVNAME);
error_regdev:
        return  err;
	// return 0;
}

/*
** Module exit function
*/
static void __exit cs614_driver_exit(void)
{
        mutex_destroy(&cs614_mutex);
        kfree(d_buf);
        device_destroy(demo_class, MKDEV(major, 0));
        class_destroy(demo_class);
        unregister_chrdev(major, DEVNAME);
        pr_info("Device Driver Remove...Done!!!\n");
        sysfs_remove_group (kernel_kobj, &traphook_attr_group);
}
 
module_init(cs614_driver_init);
module_exit(cs614_driver_exit);
 
MODULE_LICENSE("GPL");
