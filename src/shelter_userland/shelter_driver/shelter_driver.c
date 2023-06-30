#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/cma.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/dma-contiguous.h>
#include <linux/arm-smccc.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <linux/kallsyms.h>

#define DEBUGLABEL (0)

# define  U_(_x)    (_x##U)
# define   U(_x)    U_(_x)
# define  UL(_x)    (_x##UL)
# define ULL(_x)    (_x##ULL)
# define   L(_x)    (_x##L)
# define  LL(_x)    (_x##LL)

#define SMC_64              U(1)
#define SMC_TYPE_FAST           UL(1)
#define FUNCID_TYPE_SHIFT       U(31)
#define FUNCID_CC_SHIFT         U(30)
#define OEN_ARM_START           U(0)
#define FUNCID_OEN_SHIFT        U(24)
#define FUNCID_NUM_SHIFT        U(0)

#define EXCEPTION_VECTOR_LENGTH 0x1000
#define ENC_EXTEND_MEM_DEFAULT_LENGTH 0x4000000
#define SHELTER_VECTOR_PAGE_TABLE_SPACE 0x1000000


/* Get RMI fastcall std FID from function number */
#define RMI_FID(smc_cc, func_num)           \
    ((SMC_TYPE_FAST << FUNCID_TYPE_SHIFT)   |   \
    ((smc_cc) << FUNCID_CC_SHIFT)       |   \
    (OEN_ARM_START << FUNCID_OEN_SHIFT) |   \
    ((func_num) << FUNCID_NUM_SHIFT))

#define RMI_FNUM_GRAN_NS_REALM      U(1)
#define RMI_FNUM_GRAN_REALM_NS      U(2)

/* RMI SMC64 FIDs handled by the RMMD */
// NS PAS -> REALM PAS
#define RMI_RMM_GRANULE_DELEGATE    RMI_FID(SMC_64, RMI_FNUM_GRAN_NS_REALM)

//shelter api
#define ENC_DESTROY_TEST    U(0x80000FF0)
#define ENC_ENTER   U(0x80000FF1)
#define ENC_NEW_TEST    U(0x80000FFE)
#define ENC_TASK_EXIT_TEST    U(0x80000FFF)
#define ENC_STATUS    U(0x80001000)
#define ENC_MEM_EXPAND    U(0x80000F02)
#define ENC_MARK_RELEASE    U(0x80000F03)
#define ENC_ISOLATION_TEST   U(0x80001001)

/* LDD Driver Name */
#define DEV_NAME		"SHELTER"
#define ENC_REGION_NUM		64
#define ENC_MEM_ALLOCATE	_IOW('m', 1, unsigned int)
#define ENC_MEM_RELEASE		_IOW('m', 2, unsigned int)
#define ENC_MAX 0x10

size_t is_wait_released_mem[ENC_MAX];
struct arm_smccc_res smccc_res;

static long long getCycle(void){
        long long r = 0;
	asm volatile("mrs %0, pmccntr_el0" : "=r" (r)); 

        return r;
}

/* SApp CMA region information */
struct ENC_demo_info {
	unsigned long gpt_id; //SApp's GPT id
	unsigned long virt; // the first virt base address, but it is usually useless. 
	unsigned long phys; //phsy base address
	unsigned long offset; // already allocated phsy offset, each allocation invoking ENC_demo_mmap will increase this offset
	unsigned long length; // phsy memory size
	unsigned long entry; //enclave entry
    unsigned long stack_top; // the enclave stack top virt address
};

/* SApp Memory Region */
struct ENC_demo_region {
	struct ENC_demo_info info;
	struct list_head list;
};

/*  manager information */
struct ENC_demo_manager {
	struct miscdevice misc;
	struct mutex lock;
	struct list_head head;
};

/* memory device */
static struct ENC_demo_manager *manager;

//temp variable
struct ENC_demo_region *region;

//the shelter cma memory pool, for current shelter memory allocation, must be used after allocated by ENC_MEM_ALLOCATE
static struct ENC_demo_region *enclave_mems_region;

extern void __attribute__ ((visibility ("hidden"))) shelter_vector_table(void);
extern void __attribute__ ((visibility ("hidden"))) shelter_vector_end(void);

/* single physical page allocation flag*/
int single_flag = 0;

//make the memory Privileged EXEC and User EXEC
static pte_t pte_mkexec_el0(pte_t pte)
{	
	pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
	pte = set_pte_bit(pte, __pgprot(PTE_USER)); /* AP[1] */
	pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY)); /* AP[2] */
	pte = clear_pte_bit(pte, __pgprot(PTE_PXN));
	pte = clear_pte_bit(pte, __pgprot(PTE_UXN));
	if DEBUGLABEL
		pr_cont(", mk_pte_el0=%016llx", pte_val(pte));
	return pte;
}

static pte_t pte_mkexec_el1(pte_t pte)
{	
	pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
	pte = clear_pte_bit(pte, __pgprot(PTE_USER)); /* AP[1] */
	pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY)); /* AP[2] */
	pte = clear_pte_bit(pte, __pgprot(PTE_PXN));
	pte = clear_pte_bit(pte, __pgprot(PTE_UXN));
	if DEBUGLABEL
		pr_cont(", mk_pte_el1=%016llx", pte_val(pte));
	return pte;
}

static bool mk_page_memory_exec(unsigned long addr, int elx)
{
	struct mm_struct *mm;
	pgd_t *pgdp;
	pgd_t pgd;

	if (addr < TASK_SIZE) {
		/* TTBR0 */
		mm = current->active_mm;
		if (mm == &init_mm) {
			pr_alert("[%016lx] user address but active_mm is swapper\n",
				 addr);
			return false;
		}
	} else if (addr >= VA_START) {
		/* TTBR1 */
		mm = &init_mm;
	} else {
		pr_alert("[%016lx] address between user and kernel address ranges\n",
			 addr);
		return false;
	}

	if DEBUGLABEL
		pr_alert("%s pgtable: %luk pages, %u-bit VAs, pgdp = %p\n",
		 mm == &init_mm ? "swapper" : "user", PAGE_SIZE / SZ_1K,
		 mm == &init_mm ? VA_BITS : (int) vabits_user, mm->pgd);
	pgdp = pgd_offset(mm, addr);
	pgd = READ_ONCE(*pgdp);
	if DEBUGLABEL
		pr_alert("[%016lx] pgd=%016llx", addr, pgd_val(pgd));

	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep, pte;

	do {
		if (pgd_none(pgd) || pgd_bad(pgd))
			break;

		pudp = pud_offset(pgdp, addr);
		pud = READ_ONCE(*pudp);
		if DEBUGLABEL
			pr_cont(", pud=%016llx", pud_val(pud));
		if (pud_none(pud) || pud_bad(pud))
			break;

		pmdp = pmd_offset(pudp, addr);
		pmd = READ_ONCE(*pmdp);
		if DEBUGLABEL
			pr_cont(", pmd=%016llx", pmd_val(pmd));
		if (pmd_none(pmd) || pmd_bad(pmd))
			break;

		ptep = pte_offset_map(pmdp, addr);
		pte = READ_ONCE(*ptep);
		if DEBUGLABEL
			pr_cont(", pte=%016llx", pte_val(pte));
		if(elx == 0)
			set_pte(ptep, pte_mkexec_el0(*ptep));
		else
			set_pte(ptep, pte_mkexec_el1(*ptep));
		pte = READ_ONCE(*ptep);
		if DEBUGLABEL
			pr_cont(", new_pte=%016llx", pte_val(pte));
		pte_unmap(ptep);
	} while(0);
	if DEBUGLABEL
		pr_cont("\n");
	return true;
}

static bool mk_region_memory_exec(unsigned long addr, unsigned long length, int elx)
{
	int i;
	unsigned long n_pages = length >> PAGE_SHIFT;
	for (i = 0; i < n_pages; i++)
	{
		if (!mk_page_memory_exec(addr, elx))
		{
			return false;
		}
		addr+= PAGE_SIZE;
	}
	return true;
}

static int shelter_memexpand(int gpt_id)
{
	// we need to allocate a new memory region to extend shelter memory
	unsigned int pool_size_order;
	unsigned long nr_pages;
	struct page *page;
	enclave_mems_region = kzalloc(sizeof(enclave_mems_region), GFP_KERNEL);
	if (!enclave_mems_region) {
		printk(KERN_ERR "ALLOCATE: no free memory.\n");
		return -ENOMEM;
	}
	nr_pages = ENC_EXTEND_MEM_DEFAULT_LENGTH >> PAGE_SHIFT;
	pool_size_order = get_order(ENC_EXTEND_MEM_DEFAULT_LENGTH);
	page = dma_alloc_from_contiguous(NULL, nr_pages,
			pool_size_order, GFP_KERNEL);
	if (!page) {
		printk(KERN_ERR "ALLOCATE: DMA allocate error\n");
		return -ENOMEM;
	}

	/* Insert region into manager */
	enclave_mems_region->info.gpt_id = gpt_id;
	enclave_mems_region->info.virt = (dma_addr_t)page_to_virt(page);
	enclave_mems_region->info.phys = (dma_addr_t)page_to_phys(page);
	enclave_mems_region->info.length = ENC_EXTEND_MEM_DEFAULT_LENGTH;
	enclave_mems_region->info.offset = 0;
	list_add(&enclave_mems_region->list, &manager->head);
	memset(enclave_mems_region->info.virt, 0, enclave_mems_region->info.length);

	// send the mem info to el3 to update gpt for expand enclave memory
	// printk(KERN_INFO "SHELTER_MEM_EXPAND\n");
	struct arm_smccc_res smccc_res;
	arm_smccc_smc(ENC_MEM_EXPAND, enclave_mems_region->info.phys, enclave_mems_region->info.length, 0, 0, 0, 0, 0, &smccc_res);
	int ret = smccc_res.a0;
	// printk(KERN_INFO "SHELTER_MEM_EXPAND RETURN, ret:%d\n", ret);
	return ret;
}

static long ENC_demo_ioctl(struct file *filp, unsigned int cmd, 
							unsigned long arg)
{
	struct ENC_demo_region *exception_vector_region;
	struct ENC_demo_info info; //temp buffer
	int gpt_id;
	unsigned int pool_size_order;
	unsigned long nr_pages;
	struct page *page;
	int found = 0;
	int rvl;
	uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8;
    uint64_t start, end;
    uint64_t start2, end2;
	int i;

	switch (cmd) {
	case ENC_MEM_ALLOCATE:
		/* lock */
		mutex_lock(&manager->lock);
		/* Get information from userland */
		if (copy_from_user(&info, (void __user *)arg,
					sizeof(struct ENC_demo_info))) {
			printk(KERN_ERR "ALLOCATE: copy_from_user error\n");
			rvl = -EFAULT;
			goto err_user;
		}

		/* allocate new region */
		region = kzalloc(sizeof(*region), GFP_KERNEL);
		if (!region) {
			printk(KERN_ERR "ALLOCATE: no free memory.\n");
			rvl = -ENOMEM;
			goto err_alloc;
		}

		nr_pages = info.length >> PAGE_SHIFT;
		pool_size_order = get_order(info.length);
		/* Allocate memory from SHELTER driver */
		page = dma_alloc_from_contiguous(NULL, nr_pages,
				pool_size_order, GFP_KERNEL);
		if (!page) {
			printk(KERN_ERR "ALLOCATE: DMA allocate error\n");
			rvl = -ENOMEM;
			goto err_dma;
		}
		
		/* Insert region into manager */
		info.virt = (dma_addr_t)page_to_virt(page); //kernel space virtual address, not user-level
		info.phys = (dma_addr_t)page_to_phys(page);
		region->info.virt = info.virt;
		region->info.phys = info.phys;
		region->info.length = info.length;
		region->info.offset = 0;
		list_add(&region->list, &manager->head);
		memset(region->info.virt, 0, region->info.length);

		//set the allocated region->info to be the shelter mem region, 
		enclave_mems_region = region;

		/* export to userland */
		if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
			printk(KERN_ERR "ALLOCATE: copy_to_user error\n");
			rvl = -EINVAL;
			goto err_to;
		}
		/* unlock */
		mutex_unlock(&manager->lock);
		return 0;
	case ENC_MARK_RELEASE:
		gpt_id = get_current()->gpt_id;
		int is_record =0;
		for (i=0; i<ENC_MAX; i++)
		{
			if(is_wait_released_mem[i] == gpt_id)
			{
				is_record = 1;
				break;
			}	
		}
		if(is_record == 0)
		{
			for (i=0; i<ENC_MAX; i++)
			{
				if(is_wait_released_mem[i] == 0)
				{
					is_wait_released_mem[i] = gpt_id;
					break;
				}	
			}
		}	
		return 0;
	case ENC_MEM_RELEASE:
		mutex_lock(&manager->lock);
		for (i=0; i<ENC_MAX; i++)
		{
			if(is_wait_released_mem[i] == 0)
			{
				continue;
			}	
			else
			{
				gpt_id = is_wait_released_mem[i];
				/* Search region */
				list_for_each_entry(region, &manager->head, list) {
					if (region->info.gpt_id == gpt_id) {
						/* Free contiguous memory */
						page = phys_to_page(region->info.phys);
						nr_pages = region->info.length >> PAGE_SHIFT;
						dma_release_from_contiguous(NULL, page, nr_pages);
						region->info.gpt_id = 0;
						// list_del(&region->list);
						// kfree(region);
					}
				}
				is_wait_released_mem[i] == 0;
			}
		}
		mutex_unlock(&manager->lock);
		return 0;

	case ENC_STATUS:
		printk(KERN_INFO "SHELTER_STATUS\n");
		x0 = ENC_STATUS;
		printk(KERN_INFO "smc fid %llx\n", x0);
		arm_smccc_smc(x0, 0, 0, 0, 0, 0, 0, 0, &smccc_res);
		return 0;
	case ENC_NEW_TEST:
		// printk(KERN_INFO "SHELTER CREATION\n");
		mutex_lock(&manager->lock);
	
		/* require target enclave region*/
		if (!enclave_mems_region) {
			printk(KERN_ERR "NEW_TEST: Can't find avilable shelter memory region\n");
			rvl = -EINVAL;
			goto err_user;
		}
		//allocate memory for shelter exception vector
		exception_vector_region = kzalloc(sizeof(*exception_vector_region), GFP_KERNEL);
		if (!exception_vector_region) {
			printk(KERN_ERR "ALLOCATE: no free memory.\n");
			rvl = -ENOMEM;
			goto err_alloc;
		}
		nr_pages = SHELTER_VECTOR_PAGE_TABLE_SPACE >> PAGE_SHIFT;
		pool_size_order = get_order(SHELTER_VECTOR_PAGE_TABLE_SPACE);
		page = dma_alloc_from_contiguous(NULL, nr_pages,
				pool_size_order, GFP_KERNEL);
		if (!page) {
			printk(KERN_ERR "ALLOCATE: cma allocate error\n");
			rvl = -ENOMEM;
			goto err_dma;
		}
		/* Insert region into manager */
		exception_vector_region->info.virt = (dma_addr_t)page_to_virt(page);
		exception_vector_region->info.phys = (dma_addr_t)page_to_phys(page);
		exception_vector_region->info.length = SHELTER_VECTOR_PAGE_TABLE_SPACE;
		list_add(&exception_vector_region->list, &manager->head);
		memset(exception_vector_region->info.virt, 0, exception_vector_region->info.length);

		//exception vector page is exectuable
		if (!mk_region_memory_exec(exception_vector_region->info.virt, EXCEPTION_VECTOR_LENGTH, 1))
		{
			rvl = -EINVAL;
			goto err_user;
		}
		memcpy(exception_vector_region->info.virt, &shelter_vector_table, &shelter_vector_end - &shelter_vector_table);

		struct pt_regs *task_regs = task_pt_regs(get_current());
		enclave_mems_region->info.entry = task_regs->pc;
		enclave_mems_region->info.stack_top = task_regs->sp;
		x0 = ENC_NEW_TEST;
		x1 = enclave_mems_region->info.phys; //enclave memory phsy address
    	x2 = enclave_mems_region->info.stack_top; // EL0 stack sp
    	x3 = enclave_mems_region->info.entry; //EL0 enclave entry
		x4 = get_current()->fd_cma;
		x5 = exception_vector_region->info.virt; //EL1 enc_vector virt address
		x6 = enclave_mems_region->info.length;
		x7 = (unsigned long)get_current();
		mutex_unlock(&manager->lock);

		//shelter_creaion, the memory cannot be accessed by OS
		arm_smccc_smc(x0, x1, x2, x3, x4, x5, x6, x7, &smccc_res);
		asm volatile("isb");
		gpt_id = smccc_res.a0;
		if(gpt_id>0)
		{
			enclave_mems_region->info.gpt_id = gpt_id;
			exception_vector_region->info.gpt_id = gpt_id;
			int ret;
			ret = shelter_memexpand(gpt_id);
			if(ret !=0)
			{
				printk(KERN_INFO "shelter_memexpand fail\n");
				return -1;
			}
				
		}
		return gpt_id;

	case ENC_DESTROY_TEST:
		/* lock */
		mutex_lock(&manager->lock);
		/* Get information from userland */
		if (copy_from_user(&info, (void __user *)arg,
					sizeof(struct ENC_demo_info))) {
			printk(KERN_ERR "ALLOCATE: copy_from_user error\n");
			rvl = -EFAULT;
			goto err_user;
		}

		x0 = ENC_DESTROY_TEST;
		x1 = info.virt; //enclave memory phsy address
		arm_smccc_smc(x0, x1, 0, 0, 0, 0, 0, 0, &smccc_res);
		asm volatile("isb");
		mutex_unlock(&manager->lock);
		return 0;

	case ENC_ISOLATION_TEST:
		printk(KERN_INFO "ENC_ISOLATION_TEST\n");
		printk(KERN_INFO "SHELTER kernel Virt: %#lx\n", enclave_mems_region->info.virt);
		printk(KERN_INFO "Simulate malicious access the SHELTER region of first 4 bytes:%d\n", *(int*) enclave_mems_region->info.virt);
		printk(KERN_INFO "ENC_ISOLATION_TEST RETURN\n");

	default:
		printk(KERN_INFO "SHELTER not support command.\n");
		return -EFAULT;
	}

err_to:
	list_del(&region->list);
	dma_release_from_contiguous(NULL, page, nr_pages);
err_dma:
	kfree(region);
err_alloc:

err_user:
	mutex_unlock(&manager->lock);
	return rvl;

}

static int ENC_demo_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long start = vma->vm_start;
	unsigned long size = vma->vm_end - vma->vm_start;
	// unsigned long base_phsy_offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long single_page_allocation = vma->vm_pgoff;
	unsigned long phsy_page;
	unsigned long base_phsy_offset;
	unsigned int pool_size_order;
	unsigned long nr_pages;
	struct page *page;
	int ret;

	if(single_page_allocation != 1)
	{
		if (enclave_mems_region->info.offset + size <= enclave_mems_region->info.length)
		{
			if(single_flag == 0)
			{
				base_phsy_offset = enclave_mems_region->info.offset + enclave_mems_region->info.phys;
				enclave_mems_region->info.offset += size;
			}
			else
			{	
				single_flag = 0; 
				enclave_mems_region->info.offset += PAGE_SIZE;//assign a new page for allocation
				if(enclave_mems_region->info.offset + size > enclave_mems_region->info.length)
				{
					goto add_new_enc_mem;
				}
				base_phsy_offset = enclave_mems_region->info.offset + enclave_mems_region->info.phys;
				enclave_mems_region->info.offset += size;
			}
		}
		else
		{	
			goto add_new_enc_mem;
	  	}
	}
	//same page allocation 
	else
	{	
		if(size != PAGE_SIZE)
			goto inval_single_size;
		if(enclave_mems_region->info.offset + size > enclave_mems_region->info.length)
			goto add_new_enc_mem;
		single_flag = 1;
		base_phsy_offset = enclave_mems_region->info.offset + enclave_mems_region->info.phys;
	}

	/* base_phsy_offset is user level mmap base physical address */
	phsy_page = base_phsy_offset >> PAGE_SHIFT;
	vma->vm_pgoff = phsy_page;
	vma->vm_flags &= ~VM_IO;
	vma->vm_flags |= (VM_DONTEXPAND|VM_DONTDUMP|VM_READ|VM_WRITE|VM_SHARED);

	/* Remap */
	if (remap_pfn_range(vma, start, phsy_page, size, vma->vm_page_prot)) {
		printk("REMAP: failed\n");
		return -EAGAIN;
	}	
	if(current->is_shelter && current->is_created)
	{
		//sync page table to shelter
		// printk("shelter memory allocation:.tid: %d, addr: 0x%lx, size: %lu\n", current->pid, start, size);
		arm_smccc_smc(0x80000F01, current->pid, start, size, 0, 0, 0, 0, &smccc_res);
	}

	return 0;

err_no_mem:
	printk(KERN_ERR "MEMORY is not enough\n");
	return -ENOMEM;

inval_single_size:
	printk(KERN_ERR "single page size larger 4kb\n");
	return -EINVAL;

add_new_enc_mem:
	ret = shelter_memexpand(get_current()->gpt_id);
	if(ret ==0)
	{	
		if (enclave_mems_region->info.offset + size <= enclave_mems_region->info.length)
		{
			base_phsy_offset = enclave_mems_region->info.offset + enclave_mems_region->info.phys;
			enclave_mems_region->info.offset += size;
		}
		else
		{
			printk(KERN_ERR "ALLOCATE: ENC_EXTEND_MEM_DEFAULT_LENGTH is not enough\n");
			return -ENOMEM;
		}
	}
	else
	{
		printk(KERN_ERR "SHELTER_MEM_EXPAND smc handler error\n");
		return -ENOMEM;
	}
}

/* file operations */
static struct file_operations ENC_demo_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= ENC_demo_ioctl,
	.mmap		= ENC_demo_mmap,
};

/* Module initialize entry */
static int __init ENC_demo_init(void)
{	
	int rvl;

	/* ENC: Initialize device */
	manager = kzalloc(sizeof(struct ENC_demo_manager), GFP_KERNEL);
	if (!manager) {
		printk(KERN_ERR "Allocate memory failed\n");
		rvl = -ENOMEM;
		goto err_alloc;
	}

	/* Lock: initialize */
	mutex_init(&manager->lock);
	/* Misc: initialize */
	manager->misc.name  = DEV_NAME;
	manager->misc.minor = MISC_DYNAMIC_MINOR;
	manager->misc.fops  = &ENC_demo_fops;

	/* list: initialize */
	INIT_LIST_HEAD(&manager->head);

	/* Register Misc device */
	misc_register(&manager->misc);
	printk(KERN_INFO "Shelter driver load.\n");

	return 0;

err_alloc:
	return rvl;
}

/* Module exit entry */
static void __exit ENC_demo_exit(void)
{
	struct ENC_demo_region *reg;

	/* Free all region */
	mutex_lock(&manager->lock);
	list_for_each_entry(reg, &manager->head, list)
		kfree(reg);
	mutex_unlock(&manager->lock);

	/* Un-Register Misc device */
	misc_deregister(&manager->misc);
	/* free memory */
	kfree(manager);
	manager = NULL;
	printk(KERN_ERR "Shelter driver unload.\n");
}

module_init(ENC_demo_init);
module_exit(ENC_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zym");
MODULE_DESCRIPTION("Shelter Driver");
