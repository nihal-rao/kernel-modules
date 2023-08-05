#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
//#include <asm/tlbflush.h>
// #include <asm/tlb.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/mmu_notifier.h>
#include <linux/huge_mm.h>

//#include <asm-generic/tlb.h>

#include "btplus.h"

static int major;
atomic_t device_opened;
static struct class *demo_class;
struct device *demo_device;

struct kobject *cs614_kobject;
unsigned promote = 0;

static ssize_t sysfs_show(struct kobject *kobj,
						  struct kobj_attribute *attr, char *buf);
static ssize_t sysfs_store(struct kobject *kobj,
						   struct kobj_attribute *attr, const char *buf, size_t count);

struct kobj_attribute sysfs_attr;

struct address
{
	unsigned long from_addr;
	unsigned long to_addr;
};

struct input
{
	unsigned long addr;
	unsigned length;
	struct address *buff;
};

static int device_open(struct inode *inode, struct file *file)
{
	atomic_inc(&device_opened);
	try_module_get(THIS_MODULE);
	printk(KERN_INFO "Device opened successfully\n");
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	atomic_dec(&device_opened);
	module_put(THIS_MODULE);
	printk(KERN_INFO "Device closed successfully\n");

	return 0;
}

static ssize_t device_read(struct file *filp,
						   char *buffer,
						   size_t length,
						   loff_t *offset)
{
	printk("read called\n");
	return 0;
}

static ssize_t
device_write(struct file *filp, const char *buff, size_t len, loff_t *off)
{

	printk("write called\n");
	return 8;
}

// void __collapse_huge_page_copy(pte_t *pte, struct page *page,
// 				      struct vm_area_struct *vma,
// 				      unsigned long address,
// 				      spinlock_t *ptl)
// {
// 	struct page *src_page;
// 	pte_t *_pte;
// 	for (_pte = pte; _pte < pte + 512;
// 				_pte++, page++, address += PAGE_SIZE) {
// 		pte_t pteval = *_pte;
// 		src_page = pte_page(pteval);
// 		copy_user_highpage(page, src_page, address, vma);
// 			//release_pte_page(src_page);
// 		/*
// 			* ptl mostly unnecessary, but preempt has to
// 			* be disabled to update the per-cpu stats
// 			* inside page_remove_rmap().
// 			*/
// 		spin_lock(ptl);
// 		//ptep_clear(vma->vm_mm, address, _pte);
// 		//page_remove_rmap(src_page, vma, false);
// 		spin_unlock(ptl);
// 		//free_page_and_swap_cache(src_page);
// 	}
// }

// void promote_pages(struct mm_struct* mm, unsigned long address)
// {
// 	struct page *hpage;
// 	//struct mmu_notifier_range range;
// 	pmd_t *pmd, _pmd;
// 	pte_t *pte;
// 	//pgtable_t pgtable;
// 	spinlock_t *pmd_ptl, *pte_ptl;
// 	struct vm_area_struct *vma;
// 	vma = vma_lookup(mm, address);
	
// 	hpage = alloc_pages(GFP_KERNEL, 9);
// 	anon_vma_lock_write(vma->anon_vma);

// 	/*mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, NULL, mm,
// 	address, address + ((1UL)<<21));
// 	mmu_notifier_invalidate_range_start(&range);*/
	
// 	pmd = pmd_off(mm, address);
// 	pte = pte_offset_map(pmd, address);
// 	pte_ptl = pte_lockptr(mm, pmd);

// 	pmd_ptl = pmd_lock(mm, pmd);
// 	//_pmd = *pmd;
// 	//_pmd = pmdp_collapse_flush(vma, address, pmd);
// 	spin_unlock(pmd_ptl);
// 	//mmu_notifier_invalidate_range_end(&range);
// 	//tlb_remove_table_sync_one();


// 	anon_vma_unlock_write(vma->anon_vma);

// 	//__collapse_huge_page_copy(pte, hpage, vma, address, pte_ptl);
// 	pte_unmap(pte);

// 	__SetPageUptodate(hpage);
// 	//pgtable = pmd_pgtable(_pmd);
// 	//_pmd = mk_huge_pmd(hpage, vma->vm_page_prot);
// 	_pmd = pmd_mkhuge(mk_pmd(hpage, vma->vm_page_prot));
// 	_pmd = pmd_mkdirty(_pmd);
// 	if(vma->vm_flags & VM_WRITE)
// 	{	
// 		_pmd = pmd_mkwrite(_pmd);
// 	}

// 	//spin_lock(pmd_ptl);
// 	//BUG_ON(!pmd_none(*pmd));
// 	//page_add_new_anon_rmap(hpage, vma, address);
// 	//lru_cache_add_inactive_or_unevictable(hpage, vma);
// 	//pgtable_trans_huge_deposit(mm, pmd, pgtable);
// 	//set_pmd_at(mm, address, pmd, _pmd);
// 	pmd = pmd_off(mm, address);
// 	printk("earlier pmd was %lx\n", pmd->pmd);
// 	*pmd = _pmd;
// 	printk("now pmd is %lx\n", pmd->pmd);
// 	__flush_tlb_local();
// 	//update_mmu_cache_pmd(vma, address, pmd);
// 	//spin_unlock(pmd_ptl);

// 	hpage = NULL;
// }

// void scan_vma(struct mm_struct * mm, unsigned long * cursor)
// {
// 	unsigned long cval = *cursor;
// 	unsigned long cend = *cursor+((1UL)<<21);
// 	pgd_t *pgd;
// 	pte_t *ptep;
// 	pud_t *pud;
// 	pmd_t *pmd;
// 	p4d_t *p4d;
// 	for(;cval<cend;cval+=4096)
// 	{
// 		pgd = pgd_offset(mm, cval);
// 		if(pgd_none(*pgd)||pgd_bad(*pgd) || (!pgd_present(*pgd)))
// 		{	
// 			printk("invalid pgd\n");
// 			break;
// 		}
// 		printk("Valid pgd\n");
		
		
// 		p4d = p4d_offset(pgd, cval);
// 		if(p4d_none(*p4d)||p4d_bad(*p4d)||(!p4d_present(*p4d)))
// 		{	
// 			printk("invalid p4d\n");
// 			break;
// 		}
// 		printk("Valid p4d\n");
		
// 		pud = pud_offset(p4d, cval);
// 		if(pud_none(*pud)||pud_bad(*pud)||(!pud_present(*pud)))
// 		{	
// 			printk("invalid pud\n");
// 			break;
// 		}
// 		printk("Valid pud\n");
		
// 		pmd = pmd_offset(pud, cval);
// 		if(pmd_none(*pmd)||pmd_bad(*pmd)||(!pmd_present(*pmd)))
// 		{	
// 			printk("invalid pmd\n");
// 			break;
// 		}
// 		printk("Valid pmd\n");
		
// 		ptep = pte_offset_map(pmd, cval);
// 		if(!pte_present(*ptep))
// 		{
// 			pte_unmap(ptep);
// 			printk("invalid pte\n");
// 			break;
// 		}
// 		else
// 		{
// 			pte_unmap(ptep);
// 		}
// 	}
// 	if(cval==cend)
// 	{
// 		printk("this range can be promoted\n");
// 		printk("promoted address is %lx\n", *cursor);
// 		promote_pages(mm, *cursor);
		
// 	}
// 	*cursor=cval;
// }
long device_ioctl(struct file *file,
				  unsigned int ioctl_num,
				  unsigned long ioctl_param)
{
	// unsigned long addr = 1234;
	int ret = 0; // on failure return -1
	struct address *buff = NULL;
	unsigned long vma_addr = 0;
	unsigned long to_addr = 0;
	unsigned long vm_len = 0;
	unsigned length = 0;
	//unsigned long mmap_res = 0;
	struct input *ip;
	unsigned index = 0;
	struct address temp;

	unsigned long map_flags = 0x20;//map_anon
	unsigned long prot_flags = 0;
	
	unsigned long mmap_res=0;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = 0;
	char* d_buff=NULL;


	struct vma_iterator vmi;
	unsigned long hstart, hend;


	/*
	 * Switch according to the ioctl called
	 */
	switch (ioctl_num)
	{
	case IOCTL_MVE_VMA_TO:

		buff = (struct address *)vmalloc(sizeof(struct address));
		printk("move VMA at a given address");
		if (copy_from_user(buff, (char *)ioctl_param, sizeof(struct address)))
		{
			pr_err("MVE_VMA address write error\n");
			return ret;
		}
		vma_addr = buff->from_addr;
		to_addr = buff->to_addr;

		printk("address from :%lx, to:%lx \n", vma_addr, to_addr);
		vfree(buff);
		vma = vma_lookup(current->mm, to_addr);

		if (vma != NULL)
		{
			printk("to address is invalid\n");
			return -1;
		}
		vma = vma_lookup(current->mm, vma_addr);
		if (vma == NULL)
		{
			printk("vma_addr is invalid\n");
			return -1;
		}
		vm_len = vma->vm_end-vma->vm_start;
		vma = vma_lookup(current->mm, to_addr+vm_len-1);
		if(vma!=NULL)
		{
			printk("to_addr+len-1 occupied\n");
			return -1;
		}
		vma = vma_lookup(current->mm, vma_addr);
		printk("vma start is %lx end is %lx\n", vma->vm_start, vma->vm_end);
		printk("vma flags are %lx\n", vma->vm_flags);
		
		if(vma->vm_flags & 0x1)
		{
			prot_flags = prot_flags|0x1;
		}
		if(vma->vm_flags & 0x2)
		{
			prot_flags = prot_flags|0x2;
		}
		
		if(vma->vm_flags & 0x8)
		{
			map_flags = map_flags|0x01;//map_shared
		}
		else
		{
			map_flags = map_flags|0x02;
		}
		
		mmap_res = vm_mmap(NULL, to_addr, vm_len, prot_flags, map_flags, 0);
		//mmap_res = vm_mmap(NULL, to_addr, vm_len, 0x1|0x2, 0x20|0x02, 0);
		d_buff = kmalloc(sizeof(char), GFP_KERNEL);
		for(unsigned long i=0;i<vm_len;i++)
		{
			if(copy_from_user(d_buff, (char*)(vma_addr+i), 1))
			{
				printk("copy_from_user_failed\n");
				return -1;
			}
			if(copy_to_user((char*)(to_addr+i), d_buff, 1))
			{
				printk("copy_to_user failed \n");
				return -1;
			}
		}
		printk("before vm_unmap\n");
		vm_munmap(vma_addr, vm_len);
		printk("after vm_unmap\n");
		return 0;
	case IOCTL_MVE_VMA:
		buff = (struct address *)vmalloc(sizeof(struct address));
		printk("move VMA to available hole address");
		if (copy_from_user(buff, (char *)ioctl_param, sizeof(struct address)))
		{
			pr_err("MVE_VMA address write error\n");
			return ret;
		}
		vma_addr = buff->from_addr;
		printk("VMA address :%lx \n", vma_addr);
		//vfree(buff);

		vma = vma_lookup(current->mm, vma_addr);
		if (vma == NULL)
		{
			printk("vma_addr is invalid\n");
			return -1;
		}
		printk("vma start is %lx end is %lx\n", vma->vm_start, vma->vm_end);
		vm_len = vma->vm_end - vma->vm_start;
		// flush_cache_range(vma, vma->vm_start, vma->vm_end);
		for(unsigned long i=vma->vm_end;i<0x7fffffffffff-vm_len;i+=PAGE_SIZE)
		{
			if(vma_lookup(current->mm, i)==NULL && vma_lookup(current->mm, i+vm_len-1)==NULL)
			{
				to_addr=i;
				break;
			}
			else
			{
				printk("%lx checked invalid\n", i);
			}
		}
		if(to_addr==0)
		{
			printk("hole not found\n");
			return -1;
		}
		printk("to address is %lx\n", to_addr);
		
		buff->to_addr = to_addr;
		if(vma->vm_flags & 0x1)
		{
			prot_flags = prot_flags|0x1;
		}
		if(vma->vm_flags & 0x2)
		{
			prot_flags = prot_flags|0x2;
		}
		
		if(vma->vm_flags & 0x8)
		{
			map_flags = map_flags|0x01;//map_shared
		}
		else
		{
			map_flags = map_flags|0x02;
		}
		
		mmap_res = vm_mmap(NULL, to_addr, vm_len, prot_flags, map_flags, 0);
		//mmap_res = vm_mmap(NULL, to_addr, vm_len, 0x1|0x2, 0x20|0x02, 0);
		d_buff = kmalloc(sizeof(char), GFP_KERNEL);
		for(unsigned long i=0;i<vm_len;i++)
		{
			if(copy_from_user(d_buff, (char*)(vma_addr+i), 1))
			{
				printk("copy_from_user_failed\n");
				return -1;
			}
			if(copy_to_user((char*)(to_addr+i), d_buff, 1))
			{
				printk("copy_to_user failed \n");
				return -1;
			}
		}
		printk("before vm_unmap\n");
		vm_munmap(vma_addr, vm_len);
		printk("after vm_unmap\n");
		if (copy_to_user((char *)ioctl_param, buff, sizeof(struct address)))
		{
			pr_err("MVE_VMA address write error\n");
			return -1;
		}
		vfree(buff);
		return 0;
	case IOCTL_PROMOTE_VMA:
		printk("promote 4KB pages to 2\n");
		vma_iter_init(&vmi, mm, 0);
		for_each_vma(vmi, vma) 
		{
			hstart = round_up(vma->vm_start, (1UL)<<21);
			hend = round_down(vma->vm_end, (1UL)<<21);
			vm_len=vma->vm_end-vma->vm_start;
			if(vm_len==((1UL)<<23))
			{
				printk("vm start is %lx and vm end is %lx\n", vma->vm_start, vma->vm_end);
				to_addr = vma->vm_start;
				break;
			}
		}
		//scan_vma(mm, &to_addr);
		return ret;
	case IOCTL_COMPACT_VMA:
		printk("compact VMA\n");
		ip = (struct input *)vmalloc(sizeof(struct input));
		if (copy_from_user(ip, (char *)ioctl_param, sizeof(struct input)))
		{
			pr_err("MVE_MERG_VMA address write error\n");
			return ret;
		}
		vma_addr = ip->addr;
		length = ip->length;
		buff = ip->buff;
		temp.from_addr = vma_addr;
		temp.to_addr = vma_addr;
		printk("vma address:%lx, length:%u, buff:%lx\n", vma_addr, length, (unsigned long)buff);
		// populate old to new address mapping in user buffer.
		// number of entries in this buffer is equal to the number of
		// virtual pages in vma address range
		// index of moved addr in mapping table is , index = (addr-vma_address)>>12
		index = (vma_addr - vma_addr) >> 12;
		if (copy_to_user((struct address *)buff + index, &temp, sizeof(struct address)))
		{
			pr_err("COMPACT VMA read error\n");
			return ret;
		}
		vfree(ip);
		return ret;
	}
	return ret;
}

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_release,
};

static char *demo_devnode(struct device *dev, umode_t *mode)
{
	if (mode && dev->devt == MKDEV(major, 0))
		*mode = 0666;
	return NULL;
}

// Implement required logic
static ssize_t sysfs_show(struct kobject *kobj, struct kobj_attribute *attr,
						  char *buf)
{
	pr_info("sysfs read\n");
	return 0;
}

// Implement required logic
static ssize_t sysfs_store(struct kobject *kobj, struct kobj_attribute *attr,
						   const char *buf, size_t count)
{
	printk("sysfs write\n");
	return count;
}

int init_module(void)
{
	int err;
	printk(KERN_INFO "Hello kernel\n");
	major = register_chrdev(0, DEVNAME, &fops);
	err = major;
	if (err < 0)
	{
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

	printk(KERN_INFO "I was assigned major number %d. To talk to\n", major);
	atomic_set(&device_opened, 0);

	cs614_kobject = kobject_create_and_add("kobject_cs614", kernel_kobj);

	if (!cs614_kobject)
		return -ENOMEM;

	sysfs_attr.attr.name = "promote";
	sysfs_attr.attr.mode = 0666;
	sysfs_attr.show = sysfs_show;
	sysfs_attr.store = sysfs_store;

	err = sysfs_create_file(cs614_kobject, &(sysfs_attr.attr));
	if (err)
	{
		pr_info("sysfs exists:");
		goto r_sysfs;
	}
	return 0;
r_sysfs:
	kobject_put(cs614_kobject);
	sysfs_remove_file(kernel_kobj, &sysfs_attr.attr);
error_device:
	class_destroy(demo_class);
error_class:
	unregister_chrdev(major, DEVNAME);
error_regdev:
	return err;
}

void cleanup_module(void)
{
	device_destroy(demo_class, MKDEV(major, 0));
	class_destroy(demo_class);
	unregister_chrdev(major, DEVNAME);
	kobject_put(cs614_kobject);
	sysfs_remove_file(kernel_kobj, &sysfs_attr.attr);
	printk(KERN_INFO "Goodbye kernel\n");
}

MODULE_AUTHOR("cs614");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("assignment2");
