#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>

#define CRYPTOCARD_VENDOR_ID 0x1234
#define CRYPTOCARD_DEVICE_ID 0xdeba
#define MYDEVICE "cryptocard"
#define DEVNAME "cs614_device"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nihal Rao");
MODULE_DESCRIPTION("Driver for cryptocard");

static int major;
struct device *demo_device;
static struct class *demo_class;
static short mess_len;
// static char *d_buf = NULL;
uint64_t pci_start;
static bool dma_flag = false;
wait_queue_head_t wq;
static bool int_enable = false;

struct driver_data
{
	void __iomem *ptr_bar0;
	dma_addr_t dma_handle;
	void *cpu_addr;
};

struct driver_data *my_data_ptr = NULL;

uint64_t make_dma_status(bool int_enable)
{
	uint64_t dma_status=0;
	if(int_enable)
	{
		dma_status=0x4;
	}
	return dma_status;
} 

uint8_t make_mmio_status(bool int_enable)
{
	uint8_t mmio_status=0;
	if(int_enable)
	{
		mmio_status=0x80;
	}
	return mmio_status;
}

static struct pci_device_id cryptocard_ids[] = {
	{PCI_DEVICE(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID)},
	{}};
MODULE_DEVICE_TABLE(pci, cryptocard_ids);

static int demo_open(struct inode *inode, struct file *file)
{
	// atomic_inc(&device_opened);
	try_module_get(THIS_MODULE);
	printk(KERN_INFO "chDevice opened successfully\n");
	return 0;
}

static int demo_release(struct inode *inode, struct file *file)
{
	// atomic_dec(&device_opened);
	module_put(THIS_MODULE);
	printk(KERN_INFO "chDevice closed successfully\n");
	return 0;
}

static ssize_t demo_read(struct file *filp,
						 char *ubuf,
						 size_t length,
						 loff_t *offset)
{
	if (dma_flag == false)
	{
		char *x;
		x = kzalloc(length + 1, GFP_KERNEL);
		x[length] = '\0';
		printk("length is %ld", length);
		// struct driver_data *my_data = pci_get_drvdata(dev);
		while (ioread8(my_data_ptr->ptr_bar0 + 0x20) & 1)
		{
			printk("waiting\n");
		}
		for (int i = 0; i < length; i++)
		{
			x[i] = ioread8(my_data_ptr->ptr_bar0 + 0xa8 + i);
		}
		printk("x is %s", x);
		if (copy_to_user(ubuf, x, length))
		{
			kfree(x);
			return -EINVAL;
		}
		kfree(x);
		return length;
	}
	else
	{
		while (readq(my_data_ptr->ptr_bar0 + 0xa0) & 1)
		{
			// printk("dma waiting\n");
		}
		printk("in dma read %s", (char *)my_data_ptr->cpu_addr);
		if (copy_to_user(ubuf, (char *)my_data_ptr->cpu_addr, length))
		{
			return -EINVAL;
		}
		return length;
	}
}

static ssize_t
demo_write(struct file *filp, const char *buff, size_t length, loff_t *off)
{
	char *d_buf;
	uint8_t status;
	d_buf = kzalloc(length + 1, GFP_KERNEL);
	if(d_buf==NULL)
	{
		printk(KERN_INFO "couldnt allocate memory");
		return -EINVAL;
	}
	if (copy_from_user(d_buf, buff, length))
	{
		kfree(d_buf);
		return -EINVAL;
	}
	printk(KERN_INFO "In write of driver\n");
	d_buf[length] = '\0';
	mess_len = strlen(d_buf); // store the length of the stored message
	printk(KERN_INFO "Received %zu characters from the user, mess_len is %hi\n", length, mess_len);
	printk("dbuf is %s\n", d_buf);
	if (d_buf[0] == '0')
	{
		printk("performing encryption");
		if (dma_flag == false)
		{
			for (int i = 0; i < length; i++)
			{
				iowrite8(d_buf[i + 1], my_data_ptr->ptr_bar0 + 0xa8 + i);
			}
			if(int_enable)
			{
				printk("interrupt is enabled");
			}
			else
			{
				printk("interrupt is disabled");
			}

                        status = make_mmio_status(int_enable);
			printk("initial status is %x", status);
			status = status & (~(1 << 1));
			printk("status is %x", status);
			
			iowrite8(status, my_data_ptr->ptr_bar0 + 0x20);		 // mmio status
			iowrite32(length - 1, my_data_ptr->ptr_bar0 + 0x0c); // mmio msg len
			writeq(0xa8, my_data_ptr->ptr_bar0 + 0x80);			 // data address mmio
			if ((status & (1 << 7)) != 0)
			{
				printk("this is happening\n");
				wait_event_interruptible(wq, (ioread8(my_data_ptr->ptr_bar0 + 0x20) & 1) == 0);
				printk("done waiting");
			}
		}
		else
		{
			uint64_t dma_status;
			char *dma_char = (char *)my_data_ptr->cpu_addr;
			for (int i = 0; i < length; i++)
			{
				dma_char[i] = d_buf[i + 1];
			}
			writeq((uint64_t)(my_data_ptr->dma_handle), my_data_ptr->ptr_bar0 + 0x90); // writing dma handle
			writeq(length - 1, my_data_ptr->ptr_bar0 + 0x98);						   // dma msg len

			dma_status = make_dma_status(int_enable);
			printk("initial dma status is %llx", dma_status);
			dma_status = dma_status & (~(1 << 1));
			printk("dma status is %llx", dma_status);
			dma_status = dma_status | (1 << 0);
			printk("dma status is %llx", dma_status);
			writeq(dma_status, my_data_ptr->ptr_bar0 + 0xa0); // dma status, triggers dma op
			printk("in dma read, dma status is %llx", readq(my_data_ptr->ptr_bar0+0xa0));
			if ((dma_status & (1 << 2)) != 0)
			{
				printk("this is happening\n");
				wait_event_interruptible(wq, (readq(my_data_ptr->ptr_bar0 + 0xa0) & 1) == 0);
				printk("done waiting");
			}
		}
	}
	else if (d_buf[0] == '1')
	{
		printk("performing decryption");
		if (dma_flag == false)
		{
			for (int i = 0; i < length; i++)
			{
				iowrite8(d_buf[i + 1], my_data_ptr->ptr_bar0 + 0xa8 + i);
			}
			status = make_mmio_status(int_enable);
			printk("initial status is %x", status);
			status = status | (1 << 1);
			printk("status is %x", status);
			iowrite8(status, my_data_ptr->ptr_bar0 + 0x20);		 // mmio status
			iowrite32(length - 1, my_data_ptr->ptr_bar0 + 0x0c); // mmio msg len
			writeq(0xa8, my_data_ptr->ptr_bar0 + 0x80);			 // data address mmio
			if ((status & (1 << 7)) != 0)
			{
				printk("this is happening\n");
				wait_event_interruptible(wq, (ioread8(my_data_ptr->ptr_bar0 + 0x20) & 1) == 0);
				printk("done waiting");
			}
		}
		else
		{
			uint64_t dma_status;
			char *dma_char = (char *)my_data_ptr->cpu_addr;
			for (int i = 0; i < length; i++)
			{
				dma_char[i] = d_buf[i + 1];
			}
			writeq((uint64_t)(my_data_ptr->dma_handle), my_data_ptr->ptr_bar0 + 0x90); // writing dma handle
			writeq(length - 1, my_data_ptr->ptr_bar0 + 0x98);						   // dma msg len

			dma_status = make_dma_status(int_enable);
			printk("initial dma status is %llx", dma_status);
			dma_status = dma_status | (1 << 1);
			printk("dma status is %llx", dma_status);
			dma_status = dma_status | (1 << 0);
			printk("dma status is %llx", dma_status);
			writeq(dma_status, my_data_ptr->ptr_bar0 + 0xa0); // dma status, triggers dma op
			if ((dma_status & (1 << 2)) != 0)
			{
				printk("this is happening\n");
				wait_event_interruptible(wq, (readq(my_data_ptr->ptr_bar0 + 0xa0) & 1) == 0);
				printk("done waiting");
			}
		}
	}
	else if (d_buf[0] == '2')
	{
		uint8_t a;
		uint32_t k = 0;
		printk("performing set key");
		a = (uint8_t)d_buf[1];
		printk("a is %x", a);
		k = a * 256;
		a = (uint8_t)d_buf[2];
		printk("b is %x", a);
		k = k + a;
		printk("key is %x", k);
		iowrite32(k, my_data_ptr->ptr_bar0 + 0x08);
	}
	else if (d_buf[0] == '3')
	{
		uint8_t a;
		printk("changing interrupt state\n");
		a = (uint8_t)d_buf[1];
		if (a == 1)
		{
			int_enable=true;
		}
		else
		{
			int_enable=false;
		}
	}
	else if (d_buf[0] == '4')
	{
		uint8_t a;
		printk("changing dma state\n");
		a = (uint8_t)d_buf[1];
		printk("a is %d\n", a);
		if (a == 1)
		{
			dma_flag = true;
		}
		else
		{
			dma_flag = false;
		}
	}
	else if (d_buf[0]=='5')
	{
		int ret;
		uint32_t m_len;
		status = make_mmio_status(int_enable);
		printk("initial status is %x", status);
		status = status & (~(1 << 1));
		printk("status is %x", status);
		
		ret = kstrtoint(d_buf+1, 10, &m_len);
		if(ret)
		{
			printk("conversion failed");
		}
		printk("mlen is %d", m_len);
		iowrite8(status, my_data_ptr->ptr_bar0 + 0x20);		 // mmio status
		iowrite32(m_len, my_data_ptr->ptr_bar0 + 0x0c); // mmio msg len
		writeq(0xa8, my_data_ptr->ptr_bar0 + 0x80);			 // data address mmio
		if ((status & (1 << 7)) != 0)
		{
			printk("this is happening\n");
			wait_event_interruptible(wq, (ioread8(my_data_ptr->ptr_bar0 + 0x20) & 1) == 0);
			printk("done waiting");
		}
		iowrite8('\0', my_data_ptr->ptr_bar0 + 0xa8+m_len);
	}
	else if(d_buf[0]=='6')
	{
		int ret;
		uint32_t m_len;
		status = make_mmio_status(int_enable);
		printk("initial status is %x", status);
		status = status | (1 << 1);
		printk("status is %x", status);

    		ret = kstrtoint(d_buf+1, 10, &m_len);
		if(ret)
		{
			printk("conversion failed");
		}
		printk("mlen is %d", m_len);
		iowrite8(status, my_data_ptr->ptr_bar0 + 0x20);		 // mmio status
		iowrite32(m_len, my_data_ptr->ptr_bar0 + 0x0c); // mmio msg len
		writeq(0xa8, my_data_ptr->ptr_bar0 + 0x80);			 // data address mmio
		if ((status & (1 << 7)) != 0)
		{
			printk("this is happening\n");
			wait_event_interruptible(wq, (ioread8(my_data_ptr->ptr_bar0 + 0x20) & 1) == 0);
			printk("done waiting");
		}
		iowrite8('\0', my_data_ptr->ptr_bar0 + 0xa8+m_len);
	}
	printk("freeing buffer");
	kfree(d_buf);
	return length;
}

static int demo_mmap(struct file *filp, struct vm_area_struct * vma){
        io_remap_pfn_range(vma, vma->vm_start, pci_start >> PAGE_SHIFT, vma->vm_end - vma->vm_start,vma->vm_page_prot);
        return 0;
}

static struct file_operations fops = {
	.read = demo_read,
	.write = demo_write,
	.open = demo_open,
	.release = demo_release,
	.mmap = demo_mmap,
};

static char *demo_devnode(struct device *dev, umode_t *mode)
{
	if (mode && dev->devt == MKDEV(major, 0))
		*mode = 0666;
	return NULL;
}

static irqreturn_t my_irq_handler(int irq, void *data)
{
	struct driver_data *my_data;
	uint32_t isr;
	struct pci_dev *dev = (struct pci_dev *)data;
	my_data = pci_get_drvdata(dev);
	printk("Now I am in the IRQ service routine!\n");
	isr = ioread32(my_data->ptr_bar0 + 0x24);
	if (isr == 0)
	{
		return IRQ_NONE;
	}
	iowrite32(isr, my_data->ptr_bar0 + 0x64);
	wake_up_interruptible(&wq);
	return IRQ_HANDLED;
}

static int cryptocard_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int bar;
	struct driver_data *my_data;
	unsigned long mmio_start, mmio_len;
	unsigned int io_op;
	int status = pci_resource_len(dev, 0);

	printk("cryptocard - Now I am in the probe function.\n");

	printk("cryptocard - BAR0 is %d bytes in size\n", status);

	printk("cryptocard - BAR0 is mapped to 0x%llx\n", pci_resource_start(dev, 0));
	pci_start = pci_resource_start(dev, 0);

	status = pci_enable_device(dev);
	if (status < 0)
	{
		printk("cryptocard - Could not enable device\n");
		return status;
	}
	my_data = kzalloc(sizeof(struct driver_data), GFP_KERNEL);
	// my_data_ptr = kzalloc(sizeof(struct driver_data), GFP_KERNEL);
	if (!my_data)
	{
		printk("could not allocate  driver data struct\n");
		return -ENOMEM;
	}
	bar = pci_select_bars(dev, IORESOURCE_MEM);
	// bar=0;
	printk("bar is %d\n", bar);
	status = pci_request_region(dev, bar, MYDEVICE);
	if (status)
	{
		printk("could not request region\n");
		return status;
	}
	mmio_start = pci_resource_start(dev, 0);
	mmio_len = pci_resource_len(dev, 0);

	my_data->ptr_bar0 = ioremap(mmio_start, mmio_len);
	if (!(my_data->ptr_bar0))
	{
		printk("could not ioremap\n");
		return -EIO;
	}
	io_op = ioread32(my_data->ptr_bar0);
	printk("id value is %x\n", io_op);

	io_op = 0x0;
	printk("io op value was %x \n", io_op);
	iowrite32(io_op, my_data->ptr_bar0 + 0x4);
	io_op = ioread32(my_data->ptr_bar0 + 0x4);
	printk("io op value is now %x\n", io_op);

	my_data_ptr = my_data;
	status = request_irq(dev->irq, my_irq_handler, IRQF_SHARED,
						 MYDEVICE, dev);

	my_data->cpu_addr = dma_alloc_coherent(&dev->dev, 4096, &(my_data->dma_handle), GFP_KERNEL);
	init_waitqueue_head(&wq);
	if (status)
		printk("Unable to allocate interrupt, Error\n");
	pci_set_drvdata(dev, my_data);
	return 0;
}

static void cryptocard_remove(struct pci_dev *dev)
{
	int bar;
	struct driver_data *my_data = pci_get_drvdata(dev);
	printk("cryptocard - Now I am in the remove function.\n");
	bar = pci_select_bars(dev, IORESOURCE_MEM);
	// bar=0;
	free_irq(dev->irq, dev);
	dma_free_coherent(&dev->dev, 4096, my_data->cpu_addr, my_data->dma_handle);
	if (my_data)
	{
		if (my_data->ptr_bar0)
		{
			printk("iounmap happening\n");
			iounmap(my_data->ptr_bar0);
		}
		kfree(my_data);
	}

	// kfree(my_data_ptr);
	pci_disable_device(dev);
	pci_release_region(dev, bar);
}

/* PCI driver struct */
static struct pci_driver cryptocard_driver = {
	.name = MYDEVICE,
	.id_table = cryptocard_ids,
	.probe = cryptocard_probe,
	.remove = cryptocard_remove,
};

static int __init my_init(void)
{
	int err;
	printk("cryptocard - Registering the PCI device\n");
	major = register_chrdev(0, DEVNAME, &fops);
	err = major;
	if (err < 0)
	{
		printk(KERN_ALERT "Registering char device failed with %d\n", major);
	}
	demo_class = class_create(THIS_MODULE, DEVNAME);
	err = PTR_ERR(demo_class);
	if (IS_ERR(demo_class))
	{
		printk("chdev demo class error\n");
	}

	demo_class->devnode = demo_devnode;

	demo_device = device_create(demo_class, NULL,
								MKDEV(major, 0),
								NULL, DEVNAME);
	err = PTR_ERR(demo_device);
	if (IS_ERR(demo_device))
	{
		printk("chdev demo device error\n");
	}
	// d_buf = kzalloc(4096, GFP_KERNEL);
	printk(KERN_INFO "I was assigned major number %d. To talk to\n", major);
	return pci_register_driver(&cryptocard_driver);
}

/**
 * @brief This function is called, when the module is removed from the kernel
 */
static void __exit my_exit(void)
{
	printk("cryptocard - Unregistering the PCI device\n");
	// kfree(d_buf);

	device_destroy(demo_class, MKDEV(major, 0));
	class_destroy(demo_class);
	unregister_chrdev(major, DEVNAME);

	pci_unregister_driver(&cryptocard_driver);
}

module_init(my_init);
module_exit(my_exit);
