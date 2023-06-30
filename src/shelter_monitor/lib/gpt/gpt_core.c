/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include <arch.h>
#include <arch_helpers.h>
#include <lib/gpt/gpt.h>
#include <lib/smccc.h>
#include <lib/spinlock.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <smccc_helpers.h>
#if !ENABLE_RME
#error "ENABLE_RME must be enabled to use the GPT library."
#endif

/**** TOOLS ****/
long long getCycle(void){
    long long r = 0;
	asm volatile("mrs %0, pmccntr_el0" : "=r" (r)); 
    return r;
}
uint64_t start, end;

/**** SHELTER management structure ****/
#define SIGNAL_MAX 32
#define SHELTER_TASK_SHARED_LENGTH 0x10000
#define SHELTER_TASK_SIGNAL_STACK_LENGTH 0x4000
#define EXCEPTION_VECTOR_LENGTH 0x1000
#define SHELTER_VECTOR_PAGE_TABLE_SPACE 0x1000000
#define ENC_EXTEND_MEM_DEFAULT_LENGTH 0x4000000
typedef struct {
	uintptr_t plat_gpt_l0_base;
	uintptr_t plat_gpt_l1_base;
	size_t plat_gpt_l0_size;
	size_t plat_gpt_l1_size;
	unsigned int plat_gpt_pps;
	unsigned int plat_gpt_pgs;
	unsigned int plat_gpt_l0gptsz;
} gpt_config_t;

//shelter memory gpt manage
typedef struct {
	uint64_t enc_phys_pa1;	//shelter memory for .text, .data, stack, init variable
	uint64_t enc_phys_size1;
	uint64_t enc_phys_pa2; // shelter vector memory- 4KB
	uint64_t enc_phys_size2;
	uint64_t enc_phys_pa3; // shelter memory pool for object allocation and shared buffer, etc.
	uint64_t enc_phys_size3;
	uint64_t enc_phys_pa4; // standby for expanding shelter memory pool
	uint64_t enc_phys_size4;
	bool alive;
	int fd_cma;
	uint64_t shelter_vector_virt_addr;
	uint64_t os_vector_virt_addr;
	shelter_pg enc_pg;
} gpt_mem_t;

//shelter task manage
typedef struct {
	uint64_t enc_id;
	uint64_t enc_sp;
	uint64_t task_elr_el1; // used by control flow integrity
	uint64_t ret_pc_from_signal; 
	uint64_t os_TTBR0_EL1;
	uint64_t sapp_TTBR0_EL1; //shelter page table
	uint64_t task_struct_addr;
	uint64_t tid; //CTX_CONTEXTIDR_EL1, require kernel config enable to save pid in contextidr_el1
	bool inited;
	uint64_t task_sp_el1;
	
	//exception manage
	uint32_t wait_syscallno;
	bool is_wait_syscall_ret;
	uint64_t syscall_shelter_user_addr;
	uint64_t second_syscall_shelter_user_addr;
	uint64_t third_syscall_shelter_user_addr;
	uint32_t iotcl_cmd;
	uint64_t wait_data_abort_exception;
	bool is_wait_data_abort_ret;
	uint64_t far_addr;
	
	// shared memory buffer for syscall support
	uint64_t task_shared_virt;
	uint64_t task_shared_phys; 
	uint32_t task_shared_length;
	uint32_t user_buf_size;
	uint32_t second_user_buf_size;
	bool is_use_task_shared_virt;

	//futex
	uint64_t task_futex_virt;
	uint64_t task_futex_phys;
	bool is_use_task_futex_virt; 
	
	// Signal frame stack used by setup_frame to set up a separate user mode
	// stack specifically for signal handling. The registed handler addr is
	// recorded during syscall handle such as rt_sigaction. When handling a
	// signal, we first verify that the address has been registered and that the
	// pretcode on the signal stack is correct. Then we make the memory
	// inaccessible to the OS, and maintain the signal context and normal
	// context.
	uint64_t task_signal_stack_virt;
	uint64_t task_signal_stack_phys;
	uint32_t task_signal_stack_length; 
	bool is_use_task_signal_stack_virt;
	uint64_t signal_context;
	int to_be_registered_signal_no;
	uint64_t to_be_registered_signal_handler_addr;
	uint64_t registered_signal_handler_addrs[SIGNAL_MAX]; 
} shelter_task_t;

#define TASK_MAX 64
static spinlock_t gpt_lock2;
static spinlock_t pte_lock;
gpt_config_t gpt_config[ENC_MAX];
gpt_mem_t gpt_mem[ENC_MAX];
shelter_task_t shelter_tasks[TASK_MAX];
u_register_t gpccr_el3_enc[ENC_MAX];
size_t search_empty_task(){
	int i;
	for(i = 0; i < TASK_MAX; i++){
		if(!shelter_tasks[i].inited){
			return i;
		}
	}
	return 0XFF;
}

size_t search_shelter_task(u_register_t task_struct, uint64_t tid)
{
	int i;
	if (task_struct ==0)
	{
		for(i = 0; i < TASK_MAX; i++)
		{
			if(shelter_tasks[i].tid == tid && shelter_tasks[i].inited)
			{
				return i;
			}
		}
	}
	else
	{
		for(i = 0; i < TASK_MAX; i++)
		{
			if(shelter_tasks[i].task_struct_addr == task_struct && shelter_tasks[i].tid == tid && shelter_tasks[i].inited)
			{
				return i;
			}
		}
	}
	
	return 0XFF;
}

uint64_t search_registered_signal_handler(size_t task_id, uint64_t pc ){
	int i;
	for(i = 0; i < SIGNAL_MAX; i++){
		if(shelter_tasks[task_id].registered_signal_handler_addrs[i] == pc){
			return pc;
		}
	}
	return 0;
}


/**** SHELTER memory management ****/
extern int shelter_verify_sign(u_register_t base, u_register_t size);
void gpt_enable_enc(size_t enc_id);

bool shelters_gpt_memory_overlap_check(uint64_t enc_phys_pa, uint64_t enc_phys_size)
{
	int i;
	uint64_t high_bound = enc_phys_pa+ enc_phys_size;
	for(i = 0; i < ENC_MAX; i++){
		if(gpt_mem[i].alive == false)
			continue;
		if(gpt_mem[i].enc_phys_pa1)
		{
			if(enc_phys_pa>=gpt_mem[i].enc_phys_pa1 && high_bound <= gpt_mem[i].enc_phys_pa1 + gpt_mem[i].enc_phys_size1)
				return false;
		}
		
		if(gpt_mem[i].enc_phys_pa2)
		{
			if(enc_phys_pa>=gpt_mem[i].enc_phys_pa2 && high_bound <= gpt_mem[i].enc_phys_pa2 + gpt_mem[i].enc_phys_size2)
				return false;
		}

		if(gpt_mem[i].enc_phys_pa3)
		{
			if(enc_phys_pa>=gpt_mem[i].enc_phys_pa3 && high_bound <= gpt_mem[i].enc_phys_pa3 + gpt_mem[i].enc_phys_size3)
				return false;
		}

		if(gpt_mem[i].enc_phys_pa4)
		{
			if(enc_phys_pa>=gpt_mem[i].enc_phys_pa4 && high_bound <= gpt_mem[i].enc_phys_pa4 + gpt_mem[i].enc_phys_size4)
				return false;
		}
	}
	return true;
}

bool allocate_memory_check(uint64_t pa, uint64_t size, uint64_t gpt_id)
{
	uint64_t high_bound = pa+ size;
	int flag = 0;
	if(gpt_mem[gpt_id].enc_phys_pa3)
	{
		if(pa>=gpt_mem[gpt_id].enc_phys_pa3 && high_bound <= gpt_mem[gpt_id].enc_phys_pa3 + gpt_mem[gpt_id].enc_phys_size3)
				flag +=1;
	}

	if(gpt_mem[gpt_id].enc_phys_pa4)
	{
		if(pa>=gpt_mem[gpt_id].enc_phys_pa4 && high_bound <= gpt_mem[gpt_id].enc_phys_pa4 + gpt_mem[gpt_id].enc_phys_size4)
				flag +=1;
	}
	
	if(flag > 0)
		return true;
	else
		return false;
}

static inline unsigned long
copy_one_pte(pte_t *dst_pte, pte_t *src_pte, shelter_pg * enc_pg, unsigned long addr)
{
	pte_t pte = *src_pte;
	uint64_t pa = pte.pte & 0xFFFFFFFFF000;
	if(enc_pg->use_mem_pool && !allocate_memory_check(pa, S_PAGE_SIZE, enc_pg->enc_id))
	{
		VERBOSE("the pa 0x%llx is not from memory pool.\n", pa);
		// return 0;
	}
	*dst_pte = __pte(pte.pte);
	return 0;
}

static int copy_pte_range(pmd_t *dst_pmd, pmd_t *src_pmd, shelter_pg * enc_pg,
		   unsigned long addr, unsigned long addr_end)
{
	pte_t *src_pte, *dst_pte;
	dst_pte = pte_alloc(enc_pg, dst_pmd, addr);
	if (!dst_pte)
		return -ENOMEM;
	src_pte = pte_offset(src_pmd, addr);

	do {
		if (pte_none(*src_pte)) {
			if(enc_pg->use_mem_pool)
				*dst_pte = __pte(0);
			continue;
		}
		copy_one_pte(dst_pte, src_pte, enc_pg, addr);
		VERBOSE("dst_pte: 0x%llx, pte_entry: 0x%lx, src_pte: 0x%lx, addr: 0x%lx, end: 0x%lx\n",
			(uint64_t)dst_pte, pte_val(*dst_pte), pte_val(*src_pte), addr, addr_end);
	} while (dst_pte++, src_pte++, addr += S_PAGE_SIZE, addr != addr_end);

	return 0;
}

static inline int copy_pmd_range(pgd_t *dst_pud, pgd_t *src_pud, shelter_pg * enc_pg,
		unsigned long addr, unsigned long addr_end)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	dst_pmd = pmd_alloc(enc_pg, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;
	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, addr_end);
		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		if (copy_pte_range(dst_pmd, src_pmd,
						enc_pg, addr, next))
			return -ENOMEM;
		VERBOSE("dst_pmd: 0x%lx, src_pmd: 0x%lx, addr: 0x%lx, next: 0x%lx\n",
			 pmd_val(*dst_pmd), pmd_val(*src_pmd), addr, next);
	} while (dst_pmd++, src_pmd++, addr = next, addr != addr_end);
	return 0;
}

static int copy_page_range(unsigned long addr, unsigned long addr_end, shelter_pg * enc_pg, pgd_t* os_pgd)
{
	unsigned long next;
	int ret;
	pgd_t *src_pgd, *dst_pgd;

	ret = 0;
	src_pgd = pgd_offset_raw(os_pgd, addr);
	dst_pgd = pgd_offset_raw((pgd_t *) enc_pg->enc_pgd_phys_addr, addr);

	do {
		next = pgd_addr_end(addr, addr_end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if ((copy_pmd_range(dst_pgd, src_pgd,
						enc_pg, addr, next))) {
			ret = -ENOMEM;
			break;
		}
		VERBOSE("dst_pgd: 0x%lx, src_pgd: 0x%lx, addr: 0x%lx, next: 0x%lx\n",
			 pgd_val(*dst_pgd), pgd_val(*src_pgd), addr, next);
	} while (dst_pgd++, src_pgd++, addr = next, addr != addr_end);

	return ret;
}

uint64_t allocate_shelter_page_table(uint64_t enc_id, uint64_t src_ttbr0)
{
	shelter_pg * enc_pg = &gpt_mem[enc_id].enc_pg;
	enc_pg->enc_id = enc_id;
	enc_pg->enc_pgd_phys_addr = gpt_mem[enc_id].enc_phys_pa2 + EXCEPTION_VECTOR_LENGTH;
	enc_pg->enc_pmd_phys_addr = enc_pg->enc_pgd_phys_addr + S_PAGE_SIZE;
	enc_pg->enc_pte_phys_addr = enc_pg->enc_pmd_phys_addr + 512 * S_PAGE_SIZE;
	enc_pg-> pg_length = SHELTER_VECTOR_PAGE_TABLE_SPACE-EXCEPTION_VECTOR_LENGTH;
	enc_pg->enc_pmd_pages_number = 512;
	enc_pg->enc_pte_pages_number = (enc_pg->pg_length - (513*S_PAGE_SIZE)) / S_PAGE_SIZE;
	enc_pg->pmd_pages_index = 0;
	enc_pg->pte_pages_index = 0;
	NOTICE("src_ttbr0: %llx\n", src_ttbr0);
	pgd_t *os_pgd = (pgd_t*) (src_ttbr0 & 0xFFFFFFFFFFFF);
	gpt_enable_enc(enc_id);
	int ret = copy_page_range(0, VA_END, enc_pg, os_pgd);
	if(ret == 0)
		return enc_pg->enc_pgd_phys_addr;
	else 
		return 0;
}
	
int shelter_set_page(u_register_t x1,
	u_register_t x2,
	u_register_t x3,
	u_register_t x4)
{
	spin_lock(&pte_lock);
	uint64_t tid = x1;
	uint64_t addr = x2;
	uint64_t size = x3;
	uint64_t addr_end =addr + size;
	size_t task_id = search_shelter_task(0, tid);
	if (task_id == 0xFF)
	{	
		NOTICE("Fail to find task_struct in shelter_tasks in shelter_set_page\n");
		panic();
	}
	uint64_t enc_id = shelter_tasks[task_id].enc_id;
	gpt_enable_enc(enc_id);
	shelter_pg * enc_pg = &gpt_mem[enc_id].enc_pg;
	uint64_t src_ttbr0 = shelter_tasks[task_id].os_TTBR0_EL1;
	pgd_t *os_pgd = (pgd_t*) (src_ttbr0 & 0xFFFFFFFFFFFF);
	int ret = copy_page_range(addr, addr_end, enc_pg, os_pgd);
	if(ret!=0)
		goto error;
	gpt_enable_enc(0);	
	spin_unlock(&pte_lock);
	return 0;
error:;
	NOTICE("error in shelter_set_page\n");
	gpt_enable_enc(0);	
	spin_unlock(&pte_lock);
	return -ENOMEM;
}


/**** SHELTER GPT management****/
#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
/* Helper function that cleans the data cache only if it is enabled. */
static inline
	void gpt_clean_dcache_range(uintptr_t addr, size_t size)
{
	if ((read_sctlr_el3() & SCTLR_C_BIT) != 0U) {
		clean_dcache_range(addr, size);
	}
}

/* Helper function that invalidates the data cache only if it is enabled. */
static inline
	void gpt_inv_dcache_range(uintptr_t addr, size_t size)
{
	if ((read_sctlr_el3() & SCTLR_C_BIT) != 0U) {
		inv_dcache_range(addr, size);
	}
}
#endif

typedef struct l1_gpt_attr_desc {
	size_t t_sz;		/** Table size */
	size_t g_sz;		/** Granularity size */
	unsigned int p_val;	/** Associated P value */
} l1_gpt_attr_desc_t;

/*
 * Lookup table to find out the size in bytes of the L1 tables as well
 * as the index mask, given the Width of Physical Granule Size (PGS).
 * L1 tables are indexed by PA[29:p+4], being 'p' the width in bits of the
 * aforementioned Physical Granule Size.
 */
static const l1_gpt_attr_desc_t l1_gpt_attr_lookup[] = {
	[GPCCR_PGS_4K]  = {U(1) << U(17),  /* 16384B x 64bit entry = 128KB */
			   PAGE_SIZE_4KB,  /* 4KB Granularity  */
			   U(12)},
	[GPCCR_PGS_64K] = {U(1) << U(13),  /* Table size = 8KB  */
			   PAGE_SIZE_64KB, /* 64KB Granularity  */
			  U(16)},
	[GPCCR_PGS_16K] = {U(1) << U(15),  /* Table size = 32KB */
			   PAGE_SIZE_16KB, /* 16KB Granularity  */
			   U(14)}
};

typedef struct l0_gpt_attr_desc {
	size_t sz;
	unsigned int t_val_mask;
} l0_gpt_attr_desc_t;

/*
 * Lookup table to find out the size in bytes of the L0 table as well
 * as the index mask, given the Protected Physical Address Size (PPS).
 * L0 table is indexed by PA[t-1:30], being 't' the size in bits
 * of the aforementioned Protected Physical Address Size.
 */
static const l0_gpt_attr_desc_t  l0_gpt_attr_lookup[] = {

	[GPCCR_PPS_4GB]   = {U(1) << U(5),   /* 4 x 64 bit entry = 32 bytes */
			     0x3},	     /* Bits[31:30]   */

	[GPCCR_PPS_64GB]  = {U(1) << U(9),   /* 512 bytes     */
			     0x3f},	     /* Bits[35:30]   */

	[GPCCR_PPS_1TB]   = {U(1) << U(13),  /* 8KB	      */
			     0x3ff},	     /* Bits[39:30]   */

	[GPCCR_PPS_4TB]   = {U(1) << U(15),  /* 32KB	      */
			     0xfff},	     /* Bits[41:30]   */

	[GPCCR_PPS_16TB]  = {U(1) << U(17),  /* 128KB	      */
			     0x3fff},	     /* Bits[43:30]   */

	[GPCCR_PPS_256TB] = {U(1) << U(21),  /* 2MB	      */
			     0x3ffff},	     /* Bits[47:30]   */

	[GPCCR_PPS_4PB]   = {U(1) << U(25),  /* 32MB	      */
			     0x3fffff},	     /* Bits[51:30]   */

};

static unsigned int get_l1_gpt_index(unsigned int pgs, uintptr_t pa)
{
	unsigned int l1_gpt_arr_idx;

	/*
	 * Mask top 2 bits to obtain the 30 bits required to
	 * generate the L1 GPT index
	 */
	l1_gpt_arr_idx = (unsigned int)(pa & L1_GPT_INDEX_MASK);

	/* Shift by 'p' value + 4 to obtain the index */
	l1_gpt_arr_idx >>= (l1_gpt_attr_lookup[pgs].p_val + 4);

	return l1_gpt_arr_idx;
}

unsigned int plat_is_my_cpu_primary(void);



/* The granule partition tables can only be configured on BL2 */
// #ifdef IMAGE_BL2

/* Global to keep track of next available index in array of L1 GPTs */
static unsigned int l1_gpt_mem_avlbl_index[ENC_MAX];

unsigned int enc_avlbl_index = 0;

int validate_l0_gpt_params(gpt_init_params_t *params)
{
	/* Only 1GB of address space per L0 entry is allowed */
	if (params->l0gptsz != GPCCR_L0GPTSZ_30BITS) {
		WARN("Invalid L0GPTSZ %u.\n", params->l0gptsz);
	}

	/* Only 4K granule is supported for now */
	if (params->pgs != GPCCR_PGS_4K) {
		WARN("Invalid GPT PGS %u.\n", params->pgs);
		return -EINVAL;
	}

	/* Only 4GB of protected physical address space is supported for now */
	if (params->pps != GPCCR_PPS_4GB) {
		WARN("Invalid GPT PPS %u.\n", params->pps);
		return -EINVAL;
	}

	/* Check if GPT base address is aligned with the system granule */
	if (!IS_PAGE_ALIGNED(params->l0_mem_base)) {
		ERROR("Unaligned L0 GPT base address.\n");
		return -EFAULT;
	}

	/* Check if there is enough memory for L0 GPTs */
	if (params->l0_mem_size < l0_gpt_attr_lookup[params->pps].sz) {
		ERROR("Inadequate memory for L0 GPTs. ");
		ERROR("Expected 0x%lx bytes. Got 0x%lx bytes\n",
		     l0_gpt_attr_lookup[params->pps].sz,
		     params->l0_mem_size);
		return -ENOMEM;
	}

	return 0;
}

/*
 * A L1 GPT is required if any one of the following conditions is true:
 *
 * - The base address is not 1GB aligned
 * - The size of the memory region is not a multiple of 1GB
 * - A L1 GPT has been explicitly requested (attrs == PAS_REG_DESC_TYPE_TBL)
 *
 * This function:
 * - iterates over all the PAS regions to determine whether they
 *   will need a 2 stage look up (and therefore a L1 GPT will be required) or
 *   if it would be enough with a single level lookup table.
 * - Updates the attr field of the PAS regions.
 * - Returns the total count of L1 tables needed.
 *
 * In the future wwe should validate that the PAS range does not exceed the
 * configured PPS. (and maybe rename this function as it is validating PAS
 * regions).
 */
unsigned int update_gpt_type(pas_region_t *pas_regions,
				    unsigned int pas_region_cnt)
{
	unsigned int idx, cnt = 0U;

	for (idx = 0U; idx < pas_region_cnt; idx++) {
		if (PAS_REG_DESC_TYPE(pas_regions[idx].attrs) ==
						PAS_REG_DESC_TYPE_TBL) {
			cnt++;
			continue;
		}
		if (!(IS_1GB_ALIGNED(pas_regions[idx].base_pa) &&
			IS_1GB_ALIGNED(pas_regions[idx].size))) {

			/* Current region will need L1 GPTs. */
			assert(PAS_REG_DESC_TYPE(pas_regions[idx].attrs)
						== PAS_REG_DESC_TYPE_ANY);

			pas_regions[idx].attrs =
				GPT_DESC_ATTRS(PAS_REG_DESC_TYPE_TBL,
					PAS_REG_GPI(pas_regions[idx].attrs));
			cnt++;
			continue;
		}

		/* The PAS can be mapped on a one stage lookup table */
		assert(PAS_REG_DESC_TYPE(pas_regions[idx].attrs) !=
							PAS_REG_DESC_TYPE_TBL);

		pas_regions[idx].attrs = GPT_DESC_ATTRS(PAS_REG_DESC_TYPE_BLK,
					PAS_REG_GPI(pas_regions[idx].attrs));
	}

	return cnt;
}

int validate_l1_gpt_params(gpt_init_params_t *params,
				  unsigned int l1_gpt_cnt)
{
	size_t l1_gpt_sz, l1_gpt_mem_sz;

	/* Check if the granularity is supported */
	assert(xlat_arch_is_granule_size_supported(
					l1_gpt_attr_lookup[params->pgs].g_sz));


	/* Check if naturally aligned L1 GPTs can be created */
	l1_gpt_sz = l1_gpt_attr_lookup[params->pgs].g_sz;
	if (params->l1_mem_base & (l1_gpt_sz - 1)) {
		WARN("Unaligned L1 GPT base address.\n");
		return -EFAULT;
	}

	/* Check if there is enough memory for L1 GPTs */
	l1_gpt_mem_sz = l1_gpt_cnt * l1_gpt_sz;
	if (params->l1_mem_size < l1_gpt_mem_sz) {
		WARN("Inadequate memory for L1 GPTs. ");
		WARN("Expected 0x%lx bytes. Got 0x%lx bytes\n",
		     l1_gpt_mem_sz, params->l1_mem_size);
		return -ENOMEM;
	}

	VERBOSE("Requested 0x%lx bytes for L1 GPTs.\n", l1_gpt_mem_sz);
	return 0;
}

/*
 * Helper function to determine if the end physical address lies in the same GB
 * as the current physical address. If true, the end physical address is
 * returned else, the start address of the next GB is returned.
 */
static uintptr_t get_l1_gpt_end_pa(uintptr_t cur_pa, uintptr_t end_pa)
{
	uintptr_t cur_gb, end_gb;

	cur_gb = cur_pa >> ONE_GB_SHIFT;
	end_gb = end_pa >> ONE_GB_SHIFT;

	assert(cur_gb <= end_gb);

	if (cur_gb == end_gb) {
		return end_pa;
	}

	return (cur_gb + 1) << ONE_GB_SHIFT;
}

static void generate_l0_blk_desc(gpt_init_params_t *params,
				 unsigned int idx)
{
	uint64_t gpt_desc;
	uintptr_t end_addr;
	unsigned int end_idx, start_idx;
	pas_region_t *pas = params->pas_regions + idx;
	uint64_t *l0_gpt_arr = (uint64_t *)params->l0_mem_base;

	/* Create the GPT Block descriptor for this PAS region */
	gpt_desc = GPT_BLK_DESC;
	gpt_desc |= PAS_REG_GPI(pas->attrs)
		    << GPT_BLOCK_DESC_GPI_VAL_SHIFT;

	/* Start index of this region in L0 GPTs */
	start_idx = pas->base_pa >> ONE_GB_SHIFT;

	/*
	 * Determine number of L0 GPT descriptors covered by
	 * this PAS region and use the count to populate these
	 * descriptors.
	 */
	end_addr = pas->base_pa + pas->size;
	assert(end_addr \
	       <= (ULL(l0_gpt_attr_lookup[params->pps].t_val_mask + 1)) << 30);
	end_idx = end_addr >> ONE_GB_SHIFT;

	for (; start_idx < end_idx; start_idx++) {
		l0_gpt_arr[start_idx] = gpt_desc;
		VERBOSE("L0 entry (BLOCK) index %u [%p]: GPI = 0x%llx (0x%llx)\n",
			start_idx, &l0_gpt_arr[start_idx],
			(gpt_desc >> GPT_BLOCK_DESC_GPI_VAL_SHIFT) &
			GPT_L1_INDEX_MASK, l0_gpt_arr[start_idx]);
	}
}

static void generate_l0_tbl_desc_enc(size_t enc_id, gpt_init_params_t *params,
				 unsigned int idx)
{
	uint64_t gpt_desc = 0U, *l1_gpt_arr;
	uintptr_t start_pa, end_pa, cur_pa, next_pa;
	unsigned int start_idx, l1_gpt_idx;
	unsigned int p_val, gran_sz;
	pas_region_t *pas = params->pas_regions + idx;
	uint64_t *l0_gpt_base = (uint64_t *)params->l0_mem_base;
	uint64_t *l1_gpt_base = (uint64_t *)params->l1_mem_base;

	start_pa = pas->base_pa;
	end_pa = start_pa + pas->size;
	p_val = l1_gpt_attr_lookup[params->pgs].p_val;
	gran_sz = 1 << p_val;

	/*
	 * end_pa cannot be larger than the maximum protected physical memory.
	 */
	assert(((1ULL<<30) << l0_gpt_attr_lookup[params->pps].t_val_mask)
								 > end_pa);

	for (cur_pa = start_pa; cur_pa < end_pa;) {
		/*
		 * Determine the PA range that will be covered
		 * in this loop iteration.
		 */
		next_pa = get_l1_gpt_end_pa(cur_pa, end_pa);

		VERBOSE("PAS[%u]: start: 0x%lx, end: 0x%lx, next_pa: 0x%lx.\n",
		     idx, cur_pa, end_pa, next_pa);

		/* Index of this PA in L0 GPTs */
		start_idx = cur_pa >> ONE_GB_SHIFT;

		/*
		 * If cur_pa is on a 1GB boundary then determine
		 * the base address of next available L1 GPT
		 * memory region
		 */
		if (IS_1GB_ALIGNED(cur_pa)) {
			l1_gpt_arr = (uint64_t *)((uint64_t)l1_gpt_base +
					(l1_gpt_attr_lookup[params->pgs].t_sz *
					 l1_gpt_mem_avlbl_index[enc_id]));

			assert(l1_gpt_arr <
			       (l1_gpt_base + params->l1_mem_size));

			/* Create the L0 GPT descriptor for this PAS region */
			gpt_desc = GPT_TBL_DESC |
				   ((uintptr_t)l1_gpt_arr
				    & GPT_TBL_DESC_ADDR_MASK);

			l0_gpt_base[start_idx] = gpt_desc;

			/*
			 * Update index to point to next available L1
			 * GPT memory region
			 */
			l1_gpt_mem_avlbl_index[enc_id]++;
		} else {
			/* Use the existing L1 GPT */
			l1_gpt_arr = (uint64_t *)(l0_gpt_base[start_idx]
							& ~((1U<<12) - 1U));
		}

		VERBOSE("L0 entry (TABLE) index %u [%p] ==> L1 Addr 0x%llx (0x%llx)\n",
			start_idx, &l0_gpt_base[start_idx],
			(unsigned long long)(l1_gpt_arr),
			l0_gpt_base[start_idx]);


		if(enc_id > 1){
			cur_pa = next_pa;
			continue;
		}
		/*
		 * Fill up L1 GPT entries between these two
		 * addresses.
		 */
		for (; cur_pa < next_pa; cur_pa += gran_sz) {
			unsigned int gpi_idx, gpi_idx_shift;
			/* Obtain index of L1 GPT entry */
			l1_gpt_idx = get_l1_gpt_index(params->pgs, cur_pa);

			/*
			 * Obtain index of GPI in L1 GPT entry
			 * (i = PA[p_val+3:p_val])
			 */
			gpi_idx = (cur_pa >> p_val) & GPT_L1_INDEX_MASK;

			/*
			 * Shift by index * 4 to reach correct
			 * GPI entry in L1 GPT descriptor.
			 * GPI = gpt_desc[(4*idx)+3:(4*idx)]
			 */
			gpi_idx_shift = gpi_idx << 2;

			gpt_desc = l1_gpt_arr[l1_gpt_idx];

			/* Clear existing GPI encoding */
			gpt_desc &= ~(GPT_L1_INDEX_MASK << gpi_idx_shift);

			/* Set the GPI encoding */
			gpt_desc |= ((uint64_t)PAS_REG_GPI(pas->attrs)
				     << gpi_idx_shift);

			l1_gpt_arr[l1_gpt_idx] = gpt_desc;

			if (gpi_idx == 15U) {
				VERBOSE("\tEntry %u [%p] = 0x%llx\n",
					l1_gpt_idx,
					&l1_gpt_arr[l1_gpt_idx], gpt_desc);
			}
		}
	}
}

void create_gpt_enc(size_t enc_id, gpt_init_params_t *params)
{
	unsigned int idx;
	pas_region_t *pas_regions = params->pas_regions;

	VERBOSE("pgs = 0x%x, pps = 0x%x, l0gptsz = 0x%x\n",
	     params->pgs, params->pps, params->l0gptsz);
	VERBOSE("pas_region_cnt = 0x%x L1 base = 0x%lx, L1 sz = 0x%lx\n",
	     params->pas_count, params->l1_mem_base, params->l1_mem_size);

#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
	gpt_inv_dcache_range(params->l0_mem_base, params->l0_mem_size);
	gpt_inv_dcache_range(params->l1_mem_base, params->l1_mem_size);
#endif

	for (idx = 0U; idx < params->pas_count; idx++) {

		VERBOSE("PAS[%u]: base 0x%llx, sz 0x%lx, GPI 0x%x, type 0x%x\n",
		     idx, pas_regions[idx].base_pa, pas_regions[idx].size,
		     PAS_REG_GPI(pas_regions[idx].attrs),
		     PAS_REG_DESC_TYPE(pas_regions[idx].attrs));

		/* Check if a block or table descriptor is required */
		if (PAS_REG_DESC_TYPE(pas_regions[idx].attrs) ==
		     PAS_REG_DESC_TYPE_BLK) {
			generate_l0_blk_desc(params, idx);

		} else {
			generate_l0_tbl_desc_enc(enc_id, params, idx);
		}
	}

	gpt_clean_dcache_range(params->l0_mem_base, params->l0_mem_size);
	gpt_clean_dcache_range(params->l1_mem_base, params->l1_mem_size);


	/* Make sure that all the entries are written to the memory. */
	dsbishst();
}

// #endif /* IMAGE_BL2 */

int gpt_init_enc(size_t enc_id, gpt_init_params_t *params)
{

	unsigned int l1_gpt_cnt;
	int ret;

	/* Validate arguments */
	assert(params != NULL);
	assert(params->pgs <= GPCCR_PGS_16K);
	assert(params->pps <= GPCCR_PPS_4PB);
	assert(params->l0_mem_base != (uintptr_t)0);
	assert(params->l0_mem_size > 0U);
	assert(params->l1_mem_base != (uintptr_t)0);
	assert(params->l1_mem_size > 0U);
	assert(params->pas_regions != NULL);
	assert(params->pas_count > 0U);

	ret = validate_l0_gpt_params(params);
	if (ret < 0) {

		return ret;
	}

	/* Check if L1 GPTs are required and how many. */
	l1_gpt_cnt = update_gpt_type(params->pas_regions,
				     params->pas_count);
	VERBOSE("%u L1 GPTs requested.\n", l1_gpt_cnt);

	if (l1_gpt_cnt > 0U) {
		ret = validate_l1_gpt_params(params, l1_gpt_cnt);
		if (ret < 0) {
			return ret;
		}
	}
	create_gpt_enc(enc_id, params);

	gpt_config[enc_id].plat_gpt_l0_base = params->l0_mem_base;
	gpt_config[enc_id].plat_gpt_l1_base = params->l1_mem_base;
	gpt_config[enc_id].plat_gpt_l0_size = params->l0_mem_size;
	gpt_config[enc_id].plat_gpt_l1_size = params->l1_mem_size;

	/* Backup the parameters used to configure GPCCR_EL3 on every PE. */
	gpt_config[enc_id].plat_gpt_pgs = params->pgs;
	gpt_config[enc_id].plat_gpt_pps = params->pps;
	gpt_config[enc_id].plat_gpt_l0gptsz = params->l0gptsz;

#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
	gpt_clean_dcache_range((uintptr_t)&gpt_config[enc_id], sizeof(gpt_config[enc_id]));
#endif

	return 0;
}


int gpt_init(gpt_init_params_t *params)
{
	size_t enc_id = 0;
	gpt_mem[0].alive = true;
#ifdef IMAGE_BL2
	unsigned int l1_gpt_cnt;
	int ret;
#endif
	/* Validate arguments */
	assert(params != NULL);
	assert(params->pgs <= GPCCR_PGS_16K);
	assert(params->pps <= GPCCR_PPS_4PB);
	assert(params->l0_mem_base != (uintptr_t)0);
	assert(params->l0_mem_size > 0U);
	assert(params->l1_mem_base != (uintptr_t)0);
	assert(params->l1_mem_size > 0U);

#ifdef IMAGE_BL2
	/*
	 * The Granule Protection Tables are initialised only in BL2.
	 * BL31 is not allowed to initialise them again in case
	 * these are modified by any other image loaded by BL2.
	 */
	assert(params->pas_regions != NULL);
	assert(params->pas_count > 0U);
	ret = validate_l0_gpt_params(params);
	if (ret < 0) {

		return ret;
	}

	/* Check if L1 GPTs are required and how many. */
	l1_gpt_cnt = update_gpt_type(params->pas_regions,
				     params->pas_count);
	INFO("%u L1 GPTs requested.\n", l1_gpt_cnt);

	if (l1_gpt_cnt > 0U) {
		ret = validate_l1_gpt_params(params, l1_gpt_cnt);
		if (ret < 0) {
			return ret;
		}
	}

	create_gpt_enc(enc_id, params);
#else
	/* If running in BL31, only primary CPU can initialise GPTs */
	assert(plat_is_my_cpu_primary() == 1U);
	/*
	 * If the primary CPU is calling this function from BL31
	 * we expect that the tables are aready initialised from
	 * BL2 and GPCCR_EL3 is already configured with
	 * Granule Protection Check Enable bit set.
	 */
	assert((read_gpccr_el3() & GPCCR_GPC_BIT) != 0U);

#endif /* IMAGE_BL2 */

#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
	gpt_inv_dcache_range((uintptr_t)&gpt_config[enc_id], sizeof(gpt_config[enc_id]));
#endif
	gpt_config[enc_id].plat_gpt_l0_base = params->l0_mem_base;
	gpt_config[enc_id].plat_gpt_l1_base = params->l1_mem_base;
	gpt_config[enc_id].plat_gpt_l0_size = params->l0_mem_size;
	gpt_config[enc_id].plat_gpt_l1_size = params->l1_mem_size;

	/* Backup the parameters used to configure GPCCR_EL3 on every PE. */
	gpt_config[enc_id].plat_gpt_pgs = params->pgs;
	gpt_config[enc_id].plat_gpt_pps = params->pps;
	gpt_config[enc_id].plat_gpt_l0gptsz = params->l0gptsz;

#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
	gpt_clean_dcache_range((uintptr_t)&gpt_config[enc_id], sizeof(gpt_config[enc_id]));
#endif

	return 0;
}

void gpt_enable_enc(size_t enc_id)
{
	u_register_t gpccr_el3;

	/* Invalidate any stale TLB entries */
	tlbipaallos();

#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
	gpt_inv_dcache_range((uintptr_t)&gpt_config[enc_id], sizeof(gpt_config[enc_id]));
#endif

#ifdef IMAGE_BL2
	/*
	 * Granule tables must be initialised before enabling
	 * granule protection.
	 */
	assert(gpt_config[enc_id].plat_gpt_l0_base != (uintptr_t)NULL);
#endif

	//NOTICE("before gptbr_el3 %lx\n",read_gptbr_el3());
	write_gptbr_el3(gpt_config[enc_id].plat_gpt_l0_base >> GPTBR_BADDR_VAL_SHIFT);
	//NOTICE("cpu %x\n",plat_is_my_cpu_primary());
	//NOTICE("after gptbr_el3 %lx\n",read_gptbr_el3());

	/* GPCCR_EL3.L0GPTSZ */
	gpccr_el3 = SET_GPCCR_L0GPTSZ(gpt_config[enc_id].plat_gpt_l0gptsz);

	/* GPCCR_EL3.PPS */
	gpccr_el3 |= SET_GPCCR_PPS(gpt_config[enc_id].plat_gpt_pps);

	/* GPCCR_EL3.PGS */
	gpccr_el3 |= SET_GPCCR_PGS(gpt_config[enc_id].plat_gpt_pgs);

	/* Set shareability attribute to Outher Shareable */
	gpccr_el3 |= SET_GPCCR_SH(GPCCR_SH_OS);

	/* Outer and Inner cacheability set to Normal memory, WB, RA, WA. */
	gpccr_el3 |= SET_GPCCR_ORGN(GPCCR_ORGN_WB_RA_WA);
	gpccr_el3 |= SET_GPCCR_IRGN(GPCCR_IRGN_WB_RA_WA);

	/* Enable GPT */
	gpccr_el3 |= GPCCR_GPC_BIT;

	gpccr_el3_enc[enc_id] = gpccr_el3;
	write_gpccr_el3(gpccr_el3);
	dsbsy();

	VERBOSE("Granule Protection Checks enabled\n");
}

void gpt_enable(void)
{
	gpt_enable_enc(0);
	write_scr_el3(read_scr_el3() | SCR_GPF_BIT);
}

void gpt_disable(void)
{
	u_register_t gpccr_el3 = read_gpccr_el3();
	write_gpccr_el3(gpccr_el3 &= ~GPCCR_GPC_BIT);
	dsbsy();
}

#ifdef IMAGE_BL31

/*
 * Each L1 descriptor is protected by 1 spinlock. The number of descriptors is
 * equal to the size of the total protected memory area divided by the size of
 * protected memory area covered by each descriptor.
 *
 * The size of memory covered by each descriptor is the 'size of the granule' x
 * 'number of granules' in a descriptor. The former is PLAT_ARM_GPT_PGS and
 * latter is always 16.
 */
static spinlock_t gpt_lock;

static unsigned int get_l0_gpt_index(unsigned int pps, uint64_t pa)
{
	unsigned int idx;

	/* Get the index into the L0 table */
	idx = pa >> ONE_GB_SHIFT;

	/* Check if the pa lies within the PPS */
	if (idx & ~(l0_gpt_attr_lookup[pps].t_val_mask)) {
		WARN("Invalid address 0x%llx.\n", pa);
		return -EINVAL;
	}

	return idx;
}

int gpt_transition_pas_enc(size_t enc_id, uint64_t pa,
			unsigned int target_pas)
{
	int idx;
	unsigned int idx_shift;
	// unsigned int gpi;
	uint64_t gpt_l1_desc;
	uint64_t *gpt_l1_addr, *gpt_addr;

	/* Obtain the L0 GPT address. */
	gpt_addr = (uint64_t *)gpt_config[enc_id].plat_gpt_l0_base;

	/* Validate physical address and obtain index into L0 GPT table */
	idx = get_l0_gpt_index(gpt_config[enc_id].plat_gpt_pps, pa);
	if (idx < 0U) {
		return idx;
	}

	VERBOSE("PA 0x%llx, L0 base addr 0x%llx, L0 index %u\n",
					pa, (uint64_t)gpt_addr, idx);

	/* Obtain the L0 descriptor */
	gpt_l1_desc = gpt_addr[idx];

	/*
	 * Check if it is a table descriptor. Granule transition only applies to
	 * memory ranges for which L1 tables were created at boot time. So there
	 * is no possibility of splitting and coalescing tables.
	 */
	if ((gpt_l1_desc & GPT_L1_INDEX_MASK) != GPT_TBL_DESC) {
		WARN("Invalid address 0x%llx.\n", pa);
		return -EPERM;
	}

	/* Obtain the L1 table address from L0 descriptor. */
	gpt_l1_addr = (uint64_t *)(gpt_l1_desc & ~(0xFFF));

	/* Obtain the index into the L1 table */
	idx = get_l1_gpt_index(gpt_config[enc_id].plat_gpt_pgs, pa);

	VERBOSE("L1 table base addr 0x%llx, L1 table index %u\n", (uint64_t)gpt_l1_addr, idx);

	/* Lock access to the granule */
	spin_lock(&gpt_lock);

	/* Obtain the L1 descriptor */
	gpt_l1_desc = gpt_l1_addr[idx];

	/* Obtain the shift for GPI in L1 GPT entry */
	idx_shift = (pa >> 12) & GPT_L1_INDEX_MASK;
	idx_shift <<= 2;

	/* Obtain the current GPI encoding for this PA */
	// gpi = (gpt_l1_desc >> idx_shift) & GPT_L1_INDEX_MASK;


	VERBOSE("L1 table desc 0x%llx before mod \n", gpt_l1_desc);

	/* Clear existing GPI encoding */
	gpt_l1_desc &= ~(GPT_L1_INDEX_MASK << idx_shift);

	/* Transition the granule to the new PAS */
	gpt_l1_desc |= ((uint64_t)target_pas << idx_shift);

	/* Update the L1 GPT entry */
	gpt_l1_addr[idx] = gpt_l1_desc;

	VERBOSE("L1 table desc 0x%llx after mod \n", gpt_l1_desc);

	/* Make sure change is propagated to other CPUs. */
#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
	gpt_clean_dcache_range((uintptr_t)&gpt_addr[idx], sizeof(uint64_t));
#endif

	tlbi_by_pa(pa);

	/* Make sure that all the entries are written to the memory. */
	dsbishst();

	/* Unlock access to the granule */
	spin_unlock(&gpt_lock);

	return 0;
}


int gpt_transition_pas_mul_enc(size_t enc_id, uint64_t pa, uint64_t size,
			unsigned int target_pas)
{

	int idx, idx2;
	unsigned int idx_shift;
	uint64_t gpt_l1_desc;
	uint64_t *gpt_l1_addr, *gpt_addr;
	int i;

	/* Obtain the L0 GPT address. */
	gpt_addr = (uint64_t *)gpt_config[enc_id].plat_gpt_l0_base;

	/* Validate physical address and obtain index into L0 GPT table */
	idx = get_l0_gpt_index(gpt_config[0].plat_gpt_pps, pa);
	if (idx < 0U) {
		return idx;
	}

	idx2 = get_l0_gpt_index(gpt_config[0].plat_gpt_pps, pa + size - 0x1000);
	if (idx2 < 0U || idx != idx2) {
		return idx;
	}

	VERBOSE("PA 0x%llx, L0 base addr 0x%llx, L0 index %u\n",
					pa, (uint64_t)gpt_addr, idx);

	/* Obtain the L0 descriptor */
	gpt_l1_desc = gpt_addr[idx];

	/*
	 * Check if it is a table descriptor. Granule transition only applies to
	 * memory ranges for which L1 tables were created at boot time. So there
	 * is no possibility of splitting and coalescing tables.
	 */
	if ((gpt_l1_desc & GPT_L1_INDEX_MASK) != GPT_TBL_DESC) {
		WARN("Invalid address 0x%llx.\n", pa);
		return -EPERM;
	}

	/* Obtain the L1 table address from L0 descriptor. */
	gpt_l1_addr = (uint64_t *)(gpt_l1_desc & ~(0xFFF));

	/* Obtain the index into the L1 table */
	idx = get_l1_gpt_index(gpt_config[0].plat_gpt_pgs, pa);
	idx2 = get_l1_gpt_index(gpt_config[0].plat_gpt_pgs, pa + size);

	VERBOSE("L1 table base addr 0x%llx, L1 table index %u\n", (uint64_t)gpt_l1_addr, idx);

	if(idx2 - idx < 2){
		int ret = 0;
		for(i = 0; i < (size >> 12); i++){
			ret = gpt_transition_pas_enc(enc_id, pa + (i << 12), target_pas);
			if(ret!=0){
				//NOTICE("TRANS ERROR %llx %llx\n",pa, size);
			}
		}
		return 0;
	}

	/* Lock access to the granule */
	spin_lock(&gpt_lock);

	/* Obtain the L1 descriptor */
	gpt_l1_desc = gpt_l1_addr[idx];

	/* Obtain the shift for GPI in L1 GPT entry */
	idx_shift = (pa >> 12) & GPT_L1_INDEX_MASK;
	for(i = idx_shift; i < 0x10; i++){
		gpt_l1_desc &= ~(GPT_L1_INDEX_MASK << (i << 2));
		gpt_l1_desc |= ((uint64_t)target_pas << (i << 2));
	}
	gpt_l1_addr[idx] = gpt_l1_desc;
	
	gpt_l1_desc = gpt_l1_addr[idx2];
	idx_shift = ((pa + size) >> 12) & GPT_L1_INDEX_MASK;
	for(i = 0; i < idx_shift; i++){
		gpt_l1_desc &= ~(GPT_L1_INDEX_MASK << (i << 2));
		gpt_l1_desc |= ((uint64_t)target_pas << (i << 2));
	}
	gpt_l1_addr[idx2] = gpt_l1_desc;

	gpt_l1_desc = 0;
	for(i = 0; i < 0x10; i++){
		gpt_l1_desc |= ((uint64_t)target_pas << (i << 2));
	}

	for(i = idx+1; i < idx2; i++){
		gpt_l1_addr[i] = gpt_l1_desc;
	}

	VERBOSE("L1 table desc 0x%llx after mod \n", gpt_l1_desc);

	/* Make sure change is propagated to other CPUs. */
#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
	gpt_clean_dcache_range((uintptr_t)&gpt_addr[idx], sizeof(uint64_t) * (idx2 - idx));
#endif

	tlbi_by_pa(pa);

	/* Make sure that all the entries are written to the memory. */
	dsbishst();

	/* Unlock access to the granule */
	spin_unlock(&gpt_lock);

	return 0;
}

int gpt_transition_pas_mul_enc_all(uint64_t pa, uint64_t size,
			unsigned int target_pas)
{
	int i;
	int ret = 0;
	for(i = 0; i < ENC_MAX; i++){
		if(gpt_mem[i].alive == false)
			continue;
		ret = gpt_transition_pas_mul_enc(i, pa, size, target_pas);
		if(ret!=0){
			ERROR("TRANS ERROR enc_id %x pa %llx size %llx\n",i, pa, size);
		}
	}
	return 0;
}


int transition_enc_pas(size_t enc_id, uint64_t pa, uint64_t size)
{
	int ret = 0;
	ret = gpt_transition_pas_mul_enc_all(pa, size, GPI_ROOT);
	ret = gpt_transition_pas_mul_enc(enc_id, pa, size, GPI_NS);
	return ret;
}

int gpt_transition_pas(uint64_t pa,
			unsigned int src_sec_state,
			unsigned int target_pas)
{
	int idx;
	unsigned int idx_shift;
	unsigned int gpi;
	uint64_t gpt_l1_desc;
	uint64_t *gpt_l1_addr, *gpt_addr;

	/*
	 * Check if caller is allowed to transition the granule's PAS.
	 *
	 * - Secure world caller can only request S <-> NS transitions on a
	 *   granule that is already in either S or NS PAS.
	 *
	 * - Realm world caller can only request R <-> NS transitions on a
	 *   granule that is already in either R or NS PAS.
	 */
	if (src_sec_state == SMC_FROM_REALM) {
		if ((target_pas != GPI_REALM) && (target_pas != GPI_NS)) {
			WARN("Invalid caller (%s) and PAS (%d) combination.\n",
			     "realm world", target_pas);
			return -EINVAL;
		}
	} else if (src_sec_state == SMC_FROM_SECURE) {
		if ((target_pas != GPI_SECURE) && (target_pas != GPI_NS)) {
			WARN("Invalid caller (%s) and PAS (%d) combination.\n",
			     "secure world", target_pas);
			return -EINVAL;
		}
	} else {
		WARN("Invalid caller security state 0x%x\n", src_sec_state);
		return -EINVAL;
	}

	/* Obtain the L0 GPT address. */
	gpt_addr = (uint64_t *)gpt_config[0].plat_gpt_l0_base;

	/* Validate physical address and obtain index into L0 GPT table */
	idx = get_l0_gpt_index(gpt_config[0].plat_gpt_pps, pa);
	if (idx < 0U) {
		return idx;
	}

	VERBOSE("PA 0x%llx, L0 base addr 0x%llx, L0 index %u\n",
					pa, (uint64_t)gpt_addr, idx);

	/* Obtain the L0 descriptor */
	gpt_l1_desc = gpt_addr[idx];

	/*
	 * Check if it is a table descriptor. Granule transition only applies to
	 * memory ranges for which L1 tables were created at boot time. So there
	 * is no possibility of splitting and coalescing tables.
	 */
	if ((gpt_l1_desc & GPT_L1_INDEX_MASK) != GPT_TBL_DESC) {
		WARN("Invalid address 0x%llx.\n", pa);
		return -EPERM;
	}

	/* Obtain the L1 table address from L0 descriptor. */
	gpt_l1_addr = (uint64_t *)(gpt_l1_desc & ~(0xFFF));

	/* Obtain the index into the L1 table */
	idx = get_l1_gpt_index(gpt_config[0].plat_gpt_pgs, pa);

	VERBOSE("L1 table base addr 0x%llx, L1 table index %u\n", (uint64_t)gpt_l1_addr, idx);

	/* Lock access to the granule */
	spin_lock(&gpt_lock);

	/* Obtain the L1 descriptor */
	gpt_l1_desc = gpt_l1_addr[idx];

	/* Obtain the shift for GPI in L1 GPT entry */
	idx_shift = (pa >> 12) & GPT_L1_INDEX_MASK;
	idx_shift <<= 2;

	/* Obtain the current GPI encoding for this PA */
	gpi = (gpt_l1_desc >> idx_shift) & GPT_L1_INDEX_MASK;

	if (src_sec_state == SMC_FROM_REALM) {
		/*
		 * Realm world is only allowed to transition a NS or Realm world
		 * granule.
		 */
		if ((gpi != GPI_REALM) && (gpi != GPI_NS)) {
			WARN("Invalid transition request from %s.\n",
			     "realm world");
			spin_unlock(&gpt_lock);
			return -EPERM;
		}
	} else if (src_sec_state == SMC_FROM_SECURE) {
		/*
		 * Secure world is only allowed to transition a NS or Secure world
		 * granule.
		 */
		if ((gpi != GPI_SECURE) && (gpi != GPI_NS)) {
			WARN("Invalid transition request from %s.\n",
			     "secure world");
			spin_unlock(&gpt_lock);
			return -EPERM;
		}
	}
	/* We don't need an else here since we already handle that above. */

	VERBOSE("L1 table desc 0x%llx before mod \n", gpt_l1_desc);

	/* Clear existing GPI encoding */
	gpt_l1_desc &= ~(GPT_L1_INDEX_MASK << idx_shift);

	/* Transition the granule to the new PAS */
	gpt_l1_desc |= ((uint64_t)target_pas << idx_shift);

	/* Update the L1 GPT entry */
	gpt_l1_addr[idx] = gpt_l1_desc;

	VERBOSE("L1 table desc 0x%llx after mod \n", gpt_l1_desc);

	/* Make sure change is propagated to other CPUs. */
#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
	gpt_clean_dcache_range((uintptr_t)&gpt_addr[idx], sizeof(uint64_t));
#endif

	tlbi_by_pa(pa);

	/* Make sure that all the entries are written to the memory. */
	dsbishst();

	/* Unlock access to the granule */
	spin_unlock(&gpt_lock);

	return 0;
}

#endif /* IMAGE_BL31 */

static size_t build_enc_gpt()
{
	enc_avlbl_index = enc_avlbl_index + 1;
	size_t enc_id = enc_avlbl_index;

	#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
		gpt_inv_dcache_range(ARM_PAS_L1_GPT_BASE + ARM_L1_GPT_SIZE * enc_id, ARM_L1_GPT_SIZE);
	#endif

	//use shadow gpt to speed up the init
	if(enc_id > 1){
		memcpy((void *)(ARM_PAS_L1_GPT_BASE + ARM_L1_GPT_SIZE * enc_id), (void *)ARM_PAS_L1_GPT_BASE, ARM_L1_GPT_SIZE);
		#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
			gpt_clean_dcache_range(ARM_PAS_L1_GPT_BASE + ARM_L1_GPT_SIZE * enc_id, ARM_L1_GPT_SIZE);
		#endif
	}


	#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
		gpt_clean_dcache_range(ARM_PAS_L1_GPT_BASE + ARM_L1_GPT_SIZE * enc_id, ARM_L1_GPT_SIZE);
	#endif

	/* Make sure that all the entries are written to the memory. */
	dsbishst();

	pas_region_t pas_regions[] = {
		ARM_PAS_GPI_ANY,
		ARM_PAS_KERNEL,
		ARM_PAS_L0_GPT,
		ARM_PAS_L1_GPT,
		ARM_PAS_KERNEL2,
		ARM_PAS_RMM,
		ARM_PAS_EL3_DRAM,
		ARM_PAS_GPTS
	};

	gpt_init_params_t gpt_params = {
			PLATFORM_PGS,
			PLATFORM_PPS,
			PLATFORM_L0GPTSZ,
			pas_regions,
			(unsigned int)(sizeof(pas_regions)/sizeof(pas_region_t)),
			ARM_PAS_L0_GPT_BASE + ARM_L0_GPT_SIZE * enc_id, ARM_L0_GPT_SIZE,
			ARM_PAS_L1_GPT_BASE + ARM_L1_GPT_SIZE * enc_id, ARM_L1_GPT_SIZE
		};

	/* Initialise the global granule tables */
	VERBOSE("init new GPT\n");
	if (gpt_init_enc(enc_id, &gpt_params) < 0) {
		ERROR(" fail to init new GPT\n");
	}


	return enc_id;
}

size_t get_enc_id_gptbr(){
	u_register_t gptbr_el3 = read_gptbr_el3();
	//NOTICE("gptbr_el3 %lx\n",read_gptbr_el3());
	int i;
	for(i = 0; i < ENC_MAX; i++){
		if(gpt_config[i].plat_gpt_l0_base >> GPTBR_BADDR_VAL_SHIFT == gptbr_el3){
			return i;
		}
	}
	return 0XFF;
}

uint64_t get_phys_from_shelter_virt(uint64_t virt)
{	
	uint64_t par, pa;
	u_register_t scr_el3;
	// NOTICE("the virt is 0x%llx\n", virt);
	/* Doing Non-secure address translation requires SCR_EL3.NS set */
	scr_el3 = read_scr_el3();
	write_scr_el3(scr_el3 | SCR_NS_BIT);
	isb();
	if((virt&0xffff000000000000))
	{AT(ats1e1r, virt);}
	else
	{AT(ats1e0r, virt);}
	isb();

	par = read_par_el1();

	/* Restore original SCRL_EL3 */
	write_scr_el3(scr_el3);
	isb();

	/* If the translation resulted in fault, return failure */
	if ((par & PAR_F_MASK) != 0)
		return 0;

	/* Extract Physical Address from PAR */
	pa = (par & (PAR_ADDR_MASK << PAR_ADDR_SHIFT));

	//Note that the par only output the address bits[47:12] or [51:12], so we
	//add the later 12 bits to restore the correct pa
	pa = pa + (virt & 0xFFF);
	// NOTICE("the pa is 0x%llx\n", pa);
	return pa;

}

int signal_handler_addr_record(shelter_task_t *task)
{	
	u_register_t task_struct = task->task_struct_addr;
	uint64_t tid = task->tid;
	uint64_t signal_handler_addr = task->to_be_registered_signal_handler_addr;
	int sig = task->to_be_registered_signal_no;

	size_t task_id = search_shelter_task(task_struct, tid);
	if (task_id == 0xFF)
	{	
		NOTICE("Fail to find task_struct in shelter_tasks in signal_handler_addr_record\n");
		panic();
	}
	int i;
	for (i = 0; i < SIGNAL_MAX; i++)
	{
		if(shelter_tasks[task_id].registered_signal_handler_addrs[i]!=0)
		{
			continue;
		}
		else
		{
			shelter_tasks[task_id].registered_signal_handler_addrs[i] = signal_handler_addr;
			break;
		}
	}
	NOTICE("signal:%d has been registered for signal_handler_addr:0x%llx\n", sig, signal_handler_addr);
	return 0;
}

size_t strlen_for_shelter(uint64_t virt_addr)
{
	size_t len = 0;
	uint64_t dest_pa_addr = get_phys_from_shelter_virt(virt_addr);
	len = strlen((char*) dest_pa_addr);
	// NOTICE("strlen_for_shelter--len:%lu\n", len);
	return len;
}

void memcpy_for_shelter(uint64_t dest_virt_addr, uint64_t src_virt_addr, uint32_t size)
{
	// NOTICE("memcpy_for_shelter.\n");
	uint64_t src_pa_addr = get_phys_from_shelter_virt(src_virt_addr);
	uint64_t dest_pa_addr = get_phys_from_shelter_virt(dest_virt_addr);
	if(dest_pa_addr && src_pa_addr)
		memcpy((void *)dest_pa_addr, (void *)src_pa_addr, size);
}

void path_copy(uint64_t dest_addr, uint64_t src_addr, size_t path_size)
{
	// NOTICE("path_copy.\n");
	if(path_size > 4096)
			path_size = 4096;
	memcpy_for_shelter(dest_addr, src_addr, path_size);
	if(path_size == 4096)
	{	
		uint64_t pa = get_phys_from_shelter_virt(dest_addr);
		*(char*)(pa+4095) = '\0';
	}
}

void shelter_syscall_result_handle(shelter_task_t *task, cpu_context_t *src_ctx)
{	
	uint32_t sn = task->wait_syscallno;
	if(task->is_use_task_shared_virt)
	{
		gpt_transition_pas_mul_enc(0 ,task->task_shared_phys, task->task_shared_length, GPI_ROOT);
		if(sn == SYS_UNAME || sn == SYS_sysinfo || sn == SYS_FSTAT || sn == SYS_newfstatat
		|| sn == SYS_RT_SIGACTION || sn == SYS_RT_SIGPROCMASK || sn == SYS_PRLIMIT64 || sn == SYS_GETRLIMIT
		|| sn == SYS_clock_gettime || sn == SYS_pipe2)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret == 0) 
			{
				if(sn == SYS_RT_SIGACTION)
					signal_handler_addr_record(task);
				if(task->syscall_shelter_user_addr)
					memcpy_for_shelter(task->syscall_shelter_user_addr, task->task_shared_virt, task->user_buf_size);
			}		
		}
		else if (sn == SYS_READ || sn == SYS_pread64 || sn == SYS_READLINKAT || sn == SYS_getrandom)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret >0 && ret <= task->user_buf_size)
			{
				if(task->syscall_shelter_user_addr)
					memcpy_for_shelter(task->syscall_shelter_user_addr, task->task_shared_virt, ret);	
			}		
		}
		else if (sn == SYS_IOCTL)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret == 0 && task->syscall_shelter_user_addr) 
			{
				switch (task->iotcl_cmd) {
				case TCGETS:
				case TCGETS2:
				case TCGETX:
				case TCGETA:
				case TIOCGLCKTRMIOS:
				case TIOCGSOFTCAR:
				case FIOQSIZE:
				case FS_IOC_FIEMAP:
				case FIBMAP:
				case FIONREAD:
					memcpy_for_shelter(task->syscall_shelter_user_addr, task->task_shared_virt, task->user_buf_size);
					break;	
				}
			}
		}
		else if (sn == SYS_pselect6)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret > 0)
			{
				uint64_t inp = task->syscall_shelter_user_addr;
				uint64_t outp = task->second_syscall_shelter_user_addr;
				uint64_t exp = task->third_syscall_shelter_user_addr;
				uint64_t share_virt = task->task_shared_virt;
				uint64_t num = task->user_buf_size;
		        unsigned long nr = FDS_BYTES(num);
				if(inp)
				{
					memcpy_for_shelter(inp, share_virt, nr);
					share_virt += (nr+ SHARE_BUF_OFFSET);
				}
				if(outp)
				{
					memcpy_for_shelter(outp, share_virt, nr);
					share_virt += (nr+ SHARE_BUF_OFFSET);
				}
				if(exp)
				{
					memcpy_for_shelter(exp, share_virt, nr);
					share_virt += (nr+ SHARE_BUF_OFFSET);
				}
			}
		}
		else if (sn == SYS_socketpair)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret == 0)
			{
				if(task->syscall_shelter_user_addr)
				{
					int *usockvec = (int*)get_phys_from_shelter_virt(task->syscall_shelter_user_addr);
					int *share_usockvec = (int*) get_phys_from_shelter_virt(task->task_shared_virt);
					usockvec[0] = share_usockvec[0];
					usockvec[1] = share_usockvec[1];
				}		
			}
		}
		else if (sn == SYS_epoll_pwait)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret >=0)
			{
				if(task->syscall_shelter_user_addr)
				{
					int i;
					for(i=0;i<ret;i++)
					{
						memcpy_for_shelter(task->syscall_shelter_user_addr, task->task_shared_virt, task->user_buf_size);
						task->syscall_shelter_user_addr += task->user_buf_size;
						task->task_shared_virt +=task->user_buf_size;
					}	
						
				}		
			}
		}
		else if (sn == SYS_getsockname || sn == SYS_getpeername)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret == 0)
			{
				if(task->second_syscall_shelter_user_addr)
					memcpy_for_shelter(task->second_syscall_shelter_user_addr, task->task_shared_virt+SHARE_BUF_OFFSET, 4);
				int ulen = *(int*)get_phys_from_shelter_virt(task->second_syscall_shelter_user_addr);
				if(task->syscall_shelter_user_addr && ulen<= sockaddr_SIZE)
					memcpy_for_shelter(task->syscall_shelter_user_addr, task->task_shared_virt, ulen);
			}
		}
		else if (sn == SYS_accept || sn == SYS_accept4)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret>=0)
			{
				if(task->second_syscall_shelter_user_addr)
					memcpy_for_shelter(task->second_syscall_shelter_user_addr, task->task_shared_virt, 4);
				int ulen = *(int*)get_phys_from_shelter_virt(task->second_syscall_shelter_user_addr);
				if(task->syscall_shelter_user_addr && ulen<= sockaddr_SIZE)
					memcpy_for_shelter(task->syscall_shelter_user_addr, task->task_shared_virt+SHARE_BUF_OFFSET, ulen);	
			
			}
		}
		else if (sn == SYS_gettimeofday || sn == SYS_recvfrom)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret == 0 && sn == SYS_gettimeofday)
			{
				if(task->syscall_shelter_user_addr)
					memcpy_for_shelter(task->syscall_shelter_user_addr, task->task_shared_virt, task->user_buf_size);
				if(task->second_syscall_shelter_user_addr)
					memcpy_for_shelter(task->second_syscall_shelter_user_addr, task->task_shared_virt+SHARE_BUF_OFFSET, task->second_user_buf_size);
			}
			else if(ret > 0 && sn == SYS_recvfrom)
			{
				if(task->second_syscall_shelter_user_addr)
					memcpy_for_shelter(task->second_syscall_shelter_user_addr, task->task_shared_virt, task->second_user_buf_size);
				if(task->syscall_shelter_user_addr && ret <= task->user_buf_size)
					memcpy_for_shelter(task->syscall_shelter_user_addr, task->task_shared_virt+SHARE_BUF_OFFSET, ret);
			}
		}
		else if (sn == SYS_recvmsg || sn == SYS_sendmsg)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret >0)
			{
				uint64_t user_msg = task->syscall_shelter_user_addr;
				uint64_t user_msg_pa = get_phys_from_shelter_virt(user_msg);
				struct user_msghdr* user_msg_content = (struct user_msghdr* )user_msg_pa;
				struct user_msghdr* shared_user_msg_content = (struct user_msghdr* )task->task_shared_phys;
				uint64_t shared_msg_addr = task->task_shared_virt + SHARE_BUF_OFFSET;
				if(user_msg_content->msg_name)
				{
					memcpy_for_shelter(user_msg_content->msg_name, shared_msg_addr, user_msg_content->msg_namelen);
					shared_msg_addr += SHARE_BUF_OFFSET;
				}
				user_msg_content->msg_flags = shared_user_msg_content->msg_flags;
				user_msg_content->msg_controllen = shared_user_msg_content->msg_controllen;
				if(sn == SYS_recvmsg )
				{
					if(user_msg_content->msg_iov && user_msg_content->msg_iovlen >0)
					{
					int i;
					struct iovec* vec;
						for(i =0;i<user_msg_content->msg_iovlen;i++)
						{	
							uint64_t share_iov_pa = get_phys_from_shelter_virt((shared_user_msg_content->msg_iov)[i].iov_base);
							vec = (struct iovec*)share_iov_pa;
							if((vec->iov_len + shared_msg_addr) > (task->task_shared_virt + SHELTER_TASK_SHARED_LENGTH))
							{
								NOTICE("SYS_recvmsg return--the user buf size is larger than shelter shared buf.\n");
								break;
							}
							memcpy_for_shelter((user_msg_content->msg_iov)[i].iov_base, vec->iov_base, vec->iov_len);
							shared_msg_addr+= vec->iov_len;
						}	
					}	
				}	
			}
		}
		else if(sn == SYS_readv)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret >0)
			{
				unsigned long iov = task->syscall_shelter_user_addr;
				unsigned long iovcnt = task->user_buf_size;
				if(task->syscall_shelter_user_addr && iovcnt >0)
				{
					uint64_t shared_msg_addr = task->task_shared_virt + SHARE_BUF_OFFSET;
					int i;			
					struct iovec* vec = (struct iovec*)get_phys_from_shelter_virt(iov);
					struct iovec* shared_vec = (struct iovec*)task->task_shared_phys;
					for(i = 0; i < iovcnt; i++)
					{	

						if((shared_vec[i].iov_len + shared_msg_addr) > (task->task_shared_virt + SHELTER_TASK_SHARED_LENGTH) || shared_vec[i].iov_base!= shared_msg_addr )
						{
							NOTICE("SYS_readv return is not safe.\n");
							break;
						}
						memcpy_for_shelter(vec[i].iov_base, shared_msg_addr, vec[i].iov_len);
						shared_msg_addr+= vec[i].iov_len;
					}	
				}		
			}
		}
		else if(sn == SYS_ppoll)
		{
			uint64_t ret = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(ret > 0)
			{
				uint64_t ufds = task->syscall_shelter_user_addr;
				uint64_t share_virt = task->task_shared_virt;
				if(ufds)
				{
					memcpy_for_shelter(ufds, share_virt, task->user_buf_size*pollfd_SIZE);
				}
			}
		}

		memset((void *)task->task_shared_phys, 0, task->task_shared_length);
		task->is_use_task_shared_virt =false;
	}
	else if(task->is_use_task_signal_stack_virt)
	{
		if(sn == SYS_RT_SIGRETURN)
		{
			//rt_sigreturn, restore the original context for control flow check
			task->task_elr_el1 = task->ret_pc_from_signal;
			memset((void *)task->task_signal_stack_phys, 0, task->task_signal_stack_length);
			task->is_use_task_signal_stack_virt =false;
		}
	}
	else if(task->is_use_task_futex_virt)
	{
		if(sn == SYS_FUTEX)
		{
			task->is_use_task_futex_virt = false;
		}
	}
}

void syscall_paramater_handle(shelter_task_t * task, uint32_t sysno)
{	
	cpu_context_t *src_ctx  = cm_get_context(NON_SECURE);
	if(sysno == SYS_UNAME || sysno == SYS_pipe2 || sysno == SYS_sysinfo || sysno == SYS_nanosleep)
	{	
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		switch (sysno) {
		case SYS_UNAME:
			task->user_buf_size = UTSNAME_SIZE; 
			break;
		case SYS_pipe2:
			task->user_buf_size = 8;
			break;
		case SYS_sysinfo:
			task->user_buf_size = sysinfo_SIZE;
			break;
		case SYS_nanosleep:
			task->user_buf_size = __kernel_timespec_SIZE; 
			memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, task->user_buf_size);
			break;
		}
		
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_clock_gettime || sysno == SYS_FSTAT || sysno == SYS_GETRLIMIT 
	|| sysno == SYS_bind || sysno == SYS_CONNECT || sysno == SYS_getsockname ||sysno == SYS_getpeername|| sysno == SYS_setgroups)
	{
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		uint64_t gidsetsize;
		switch (sysno) {
		case SYS_clock_gettime:
			task->user_buf_size = __kernel_timespec_SIZE; 
			break;
		case SYS_FSTAT:
			task->user_buf_size = STAT_SIZE; 
			break;
		case SYS_GETRLIMIT:
			task->user_buf_size = RLIMIT_SIZE; 
			break;
		case SYS_bind:
		case SYS_CONNECT:
			task->user_buf_size = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
			memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, task->user_buf_size); 
			break;
		case SYS_getsockname:
		case SYS_getpeername:
			task->second_syscall_shelter_user_addr = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
			memcpy_for_shelter(task->task_shared_virt+SHARE_BUF_OFFSET, task->second_syscall_shelter_user_addr, 4);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt+SHARE_BUF_OFFSET);
			break;
		case SYS_setgroups:
			gidsetsize = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
			if(gidsetsize <= 16384)
			{
				task->user_buf_size = gidsetsize * sizeof(int);
				memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, task->user_buf_size);
			}
		}
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_sendfile)
	{
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt);
		memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, sizeof(long long)); 
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_socketpair || sysno == SYS_epoll_ctl)
	{
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3);
		if(sysno == SYS_socketpair)
			task->user_buf_size = 4; 
		else if(sysno == SYS_epoll_ctl)
		{
			task->user_buf_size = epoll_event_SIZE; 
			memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, task->user_buf_size); 
		}
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_ppoll)
	{
		uint64_t num_fds = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		uint64_t ufds = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		uint64_t tsp = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		uint64_t sigmask = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3);
		uint64_t share_virt = task->task_shared_virt;
		task->syscall_shelter_user_addr = ufds;
		task->user_buf_size = num_fds;
		uint64_t MAX_LIMIT_BUF = task->task_shared_virt+task->task_shared_length;
		if(ufds)
		{
			if(share_virt + num_fds*pollfd_SIZE > MAX_LIMIT_BUF)
				goto out;
			memcpy_for_shelter(share_virt, ufds, num_fds*pollfd_SIZE);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0, share_virt);
			share_virt += num_fds*pollfd_SIZE+SHARE_BUF_OFFSET;
		}
		if(tsp)
		{
			if(share_virt + __kernel_timespec_SIZE > MAX_LIMIT_BUF)
				goto out;
			memcpy_for_shelter(share_virt, tsp, __kernel_timespec_SIZE);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, share_virt);
			share_virt += SHARE_BUF_OFFSET;
		}
		if(sigmask)
		{
			if(share_virt + SIGSET_SIZE > MAX_LIMIT_BUF)
				goto out;
			memcpy_for_shelter(share_virt, sigmask, SIGSET_SIZE);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3, share_virt);
			share_virt += SHARE_BUF_OFFSET;
		}
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_pselect6)
	{
		uint64_t num = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		uint64_t tsp = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X4);
		uint64_t inp = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		uint64_t outp = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		uint64_t exp = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3);
		uint64_t sigmask = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X5);
		uint64_t share_virt = task->task_shared_virt;
		task->syscall_shelter_user_addr = inp;
		task->second_syscall_shelter_user_addr = outp;
		task->third_syscall_shelter_user_addr = exp;
		task->user_buf_size = num;
		unsigned long nr = FDS_BYTES(num);
		if(inp)
		{
			memcpy_for_shelter(share_virt, inp, nr);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, share_virt);
			share_virt += (nr+ SHARE_BUF_OFFSET);
		}
		if(outp)
		{
			memcpy_for_shelter(share_virt, outp, nr);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, share_virt);
			share_virt += (nr+SHARE_BUF_OFFSET);
		}
		if(exp)
		{
			memcpy_for_shelter(share_virt, exp, nr);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3, share_virt);
			share_virt += (nr+SHARE_BUF_OFFSET);
		}
		if(tsp)
		{
			memcpy_for_shelter(share_virt, tsp, __kernel_timespec_SIZE);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X4, share_virt);
			share_virt += SHARE_BUF_OFFSET;
		}
		if(sigmask)
		{
			memcpy_for_shelter(share_virt, sigmask, SIGSET_SIZE);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X5, share_virt);
			share_virt += SHARE_BUF_OFFSET;
		}
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_accept || sysno == SYS_accept4)
	{
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		task->second_syscall_shelter_user_addr = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		memcpy_for_shelter(task->task_shared_virt, task->second_syscall_shelter_user_addr, 4); 
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt);
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt+SHARE_BUF_OFFSET);
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_clone)
	{
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		task->second_syscall_shelter_user_addr = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3);
		uint64_t pa;
		if((pa = get_phys_from_shelter_virt(task->syscall_shelter_user_addr))!=0)
			gpt_transition_pas_mul_enc(0, pa, S_PAGE_SIZE, GPI_NS);
		if((pa = get_phys_from_shelter_virt(task->second_syscall_shelter_user_addr))!=0)
			gpt_transition_pas_mul_enc(0, pa, S_PAGE_SIZE, GPI_NS);
	}
	else if(sysno == SYS_setsockopt)
	{
		int optname =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3);
		switch (optname)
		{
			case SO_LINGER:
			case SO_ATTACH_FILTER:
				task->user_buf_size = 128; 
				break;
		}
		memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, task->user_buf_size); 
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if(sysno == SYS_gettimeofday)
	{
		unsigned long __kernel_old_timeval =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		unsigned long timezone =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		if(__kernel_old_timeval)
		{
			task->syscall_shelter_user_addr =  __kernel_old_timeval;
			task->user_buf_size = timeval_SIZE; 
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0, task->task_shared_virt);
			task->is_use_task_shared_virt =true;
		}
		if(timezone)
		{
			task->second_syscall_shelter_user_addr =  timezone;
			task->second_user_buf_size = timezone_SIZE; 
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt+SHARE_BUF_OFFSET);
			task->is_use_task_shared_virt =true;
		}
	}
	else if (sysno == SYS_newfstatat)
	{
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2); //buf
		task->user_buf_size = STAT_SIZE;
		uint64_t buf_path_addr = task->task_shared_virt + SHELTER_TASK_SHARED_LENGTH - 4096;
		uint64_t src_path_addr = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1); //path
		size_t path_size = strlen_for_shelter(src_path_addr) +1;
		path_copy(buf_path_addr, src_path_addr, path_size);

		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, buf_path_addr);	
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if(sysno == SYS_WRITE || sysno == SYS_pwrite64)
	{
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		task->user_buf_size = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2); 
		if(task->user_buf_size > SHELTER_TASK_SHARED_LENGTH)
		{
			NOTICE("syscall_paramater_handle:sysno: %u, the user buf size is larger than shelter shared buf. The current shelter implementation will tranucate the write buf.\n", sysno);
			task->user_buf_size = SHELTER_TASK_SHARED_LENGTH;
		}
		memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, task->user_buf_size); 
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if(sysno == SYS_READ || sysno == SYS_pread64)
	{
		uint64_t fd = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		task->user_buf_size = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2); 
		if(task->user_buf_size > SHELTER_TASK_SHARED_LENGTH)
		{
			NOTICE("syscall_paramater_handle:sysno: %u, fd:%llu, the user buf size is larger than shelter shared buf. The current shelter implementation will tranucate the read buf.\n", sysno, fd);
			task->user_buf_size = SHELTER_TASK_SHARED_LENGTH;
		} 
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_OPENAT || sysno == SYS_unlinkat || sysno == SYS_fchmodat || sysno == SYS_mkdirat 
	|| sysno == SYS_renameat || sysno == SYS_renameat2)
	{
		uint64_t filename_path_addr = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1); //path
		size_t path_size;
		if(filename_path_addr)
		{
			path_size = strlen_for_shelter(filename_path_addr) +1;
			path_copy(task->task_shared_virt, filename_path_addr, path_size);
		}
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt);
		if(sysno == SYS_renameat || sysno == SYS_renameat2)
		{
			uint64_t new_filename_path_addr = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3); //path
			if(new_filename_path_addr)
			{
				path_size = strlen_for_shelter(new_filename_path_addr) +1;
				path_copy(task->task_shared_virt+SHARE_BUF_OFFSET, new_filename_path_addr, path_size);
			}
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3, task->task_shared_virt+SHARE_BUF_OFFSET);
		}
		task->is_use_task_shared_virt =true;	
	}
	else if(sysno == SYS_READLINKAT)
	{	
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2); //buf
		task->user_buf_size =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3); //bufsize
		if(task->user_buf_size > SHELTER_TASK_SHARED_LENGTH)
		{
			NOTICE("syscall_paramater_handle: SYS_READLINKAT the user buf size is larger than shelter shared buf.\n");
			task->user_buf_size = SHELTER_TASK_SHARED_LENGTH;
		}
		uint64_t buf_path_addr = task->task_shared_virt + SHELTER_TASK_SHARED_LENGTH - 4096;
		uint64_t src_path_addr = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1); //path
		size_t path_size = strlen_for_shelter(src_path_addr) +1;
		path_copy(buf_path_addr, src_path_addr, path_size);

		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, buf_path_addr);	
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
		
	}
	else if(sysno == SYS_IOCTL)
	{	
		//For each cmd must be prepared separately according to the
		//specifications of the subcommands
		unsigned int fd = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		unsigned int cmd = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		unsigned long arg = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		NOTICE("syscall parameter ioctl: fd:%u, cmd: %u, arg: %lu\n", fd, cmd, arg);
		switch (cmd) {
		//kernel to user
		case TCGETS:
		case TCGETS2:
		case TCGETX:
		case TCGETA:
		case TIOCGLCKTRMIOS:
		case TIOCGSOFTCAR:
		case FIOQSIZE:
		case FIGETBSZ:
		case FIONREAD:
			task->iotcl_cmd = cmd;
			task->syscall_shelter_user_addr = arg;
			if(cmd == TCGETS || cmd == TIOCGLCKTRMIOS)
				task->user_buf_size = TERMIOS_SIZE; 
			else if(cmd == TCGETX)
				task->user_buf_size = TERMIOX_SIZE; 
			else if(cmd == TCGETS2)
				task->user_buf_size = TERMIOS2_SIZE; 
			else if(cmd == TCGETA)
				task->user_buf_size = TERMIO_SIZE;
			else if (cmd == TIOCGSOFTCAR || cmd == FIGETBSZ || cmd == FIONREAD)
				task->user_buf_size = sizeof(int);
			else if (cmd == FIOQSIZE)
				task->user_buf_size = sizeof(long long);
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt);
			task->is_use_task_shared_virt =true;
			break;
		//user to kernel
		case TCSETSF:
		case TCSETSW:
		case TCSETS:
		case TCSETSF2:
		case TCSETSW2:
		case TCSETS2:
		case TCSETAF:
		case TCSETAW:
		case TCSETA:
		case TIOCSLCKTRMIOS:
		case TCSETX:
		case TCSETXW:
		case TCSETXF:
		case TIOCSSOFTCAR:
		case FIONBIO:
		case FIOASYNC:
		case FS_IOC_FIEMAP:
		case FICLONERANGE:
		case FIBMAP:
		case FS_IOC_RESVSP:
		case FS_IOC_RESVSP64:
			task->iotcl_cmd = cmd;
			task->syscall_shelter_user_addr = arg;
			if(cmd == TCSETSF || cmd == TCSETSW || cmd == TCSETS || cmd == TIOCSLCKTRMIOS)
				task->user_buf_size = TERMIOS_SIZE;
			else if(cmd == TCSETSF2 || cmd == TCSETSW2 || cmd == TCSETS2)
				task->user_buf_size = TERMIOS2_SIZE;
			else if(cmd == TCSETAF || cmd == TCSETAW || cmd == TCSETA)
				task->user_buf_size = TERMIO_SIZE;
			else if (cmd == TCSETX || cmd == TCSETXW || cmd == TCSETXF)
				task->user_buf_size = TERMIOX_SIZE;
			else if (cmd == TIOCGSOFTCAR || cmd == FIONBIO || cmd == FIOASYNC || cmd == FIBMAP)
				task->user_buf_size = sizeof(int);
			else if(cmd == FS_IOC_FIEMAP || FICLONERANGE)
				task->user_buf_size = fiemap_SIZE;
			else if (cmd == FS_IOC_RESVSP64 ||cmd == FS_IOC_RESVSP)
				task->user_buf_size = space_resv_SIZE;
			memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, task->user_buf_size); 
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt);
			task->is_use_task_shared_virt =true;
			break;
		}
	}
	else if (sysno == SYS_RT_SIGACTION)
	{
		unsigned long act =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		unsigned long oact =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		struct sigaction *a = (struct sigaction *)get_phys_from_shelter_virt(act);
		//tracks signal handler installation, and truly record it after the syscall return successfully
		task->to_be_registered_signal_handler_addr = a->sa_handler;
		task->to_be_registered_signal_no = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		NOTICE("In syscall parameter, signal:%d, to be registered addr:0x%llx\n",task->to_be_registered_signal_no, task->to_be_registered_signal_handler_addr);
		if(oact)
			task->syscall_shelter_user_addr =  oact;
		task->user_buf_size = SIGACTION_SIZE; 
		memcpy_for_shelter(task->task_shared_virt+SHARE_BUF_OFFSET, act, task->user_buf_size); 
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt+SHARE_BUF_OFFSET);
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_RT_SIGRETURN)
	{
		//enable the accessibility to the OS to restore context
		task->is_use_task_signal_stack_virt =true;
	}
	else if (sysno == SYS_FUTEX)
	{
		task->task_futex_virt =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		task->task_futex_phys = get_phys_from_shelter_virt(task->task_futex_virt);
		task->is_use_task_futex_virt = true;
	}
	else if (sysno == SYS_RT_SIGPROCMASK)
	{
		unsigned long new_set =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		unsigned long old_set =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		task->user_buf_size = SIGSET_SIZE; 
		if(new_set)
		{
			memcpy_for_shelter(task->task_shared_virt+SHARE_BUF_OFFSET, new_set, task->user_buf_size); 
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt+SHARE_BUF_OFFSET);
		}
		if(old_set)
			task->syscall_shelter_user_addr =  old_set;
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_PRLIMIT64)
	{
		unsigned long new_rlim =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		unsigned long old_rlim =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3);
		task->user_buf_size = RLIMIT64_SIZE; 
		if(new_rlim)
		{
			memcpy_for_shelter(task->task_shared_virt+SHARE_BUF_OFFSET, new_rlim, task->user_buf_size); 
			write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->task_shared_virt+SHARE_BUF_OFFSET);
		}
		if(old_rlim)
			task->syscall_shelter_user_addr =  old_rlim;
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X3, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}

	else if(sysno == SYS_MUNMAP)
	{
		unsigned long addr = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		unsigned long len = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		NOTICE("In syscall parameter munmap addr:%lx, len:%ld\n", addr, len);
	}

	else if (sysno == SYS_epoll_pwait)
	{
		unsigned long epoll_event = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		unsigned long sigset_t = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X4);
		task->syscall_shelter_user_addr =  epoll_event;
		task->second_syscall_shelter_user_addr = sigset_t;
		task->user_buf_size = epoll_event_SIZE; 
		if(task->second_syscall_shelter_user_addr)
			memcpy_for_shelter(task->task_shared_virt+SHARE_BUF_OFFSET, task->second_syscall_shelter_user_addr, SIGSET_SIZE); 
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt);
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X4, task->task_shared_virt+SHARE_BUF_OFFSET);
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_writev)
	{
		unsigned long iov = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		unsigned long iovcnt = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		task->syscall_shelter_user_addr = iov;
		task->user_buf_size = iovec_SIZE;
		if(task->syscall_shelter_user_addr && iovcnt >0)
		{
			int i;
			struct iovec* vec;
			uint64_t share_virt = task->task_shared_virt;
			uint64_t buf_offset = task->task_shared_virt+SHARE_BUF_OFFSET;
			for(i =0;i<iovcnt;i++)
			{	
				if(iov)
				{
					memcpy_for_shelter(share_virt, iov, task->user_buf_size); 
					uint64_t iov_pa = get_phys_from_shelter_virt(iov);
					vec = (struct iovec*)iov_pa;
					if((vec->iov_len + buf_offset) > (task->task_shared_virt+SHELTER_TASK_SHARED_LENGTH))
					{
						NOTICE("syscall_paramater_handle:SYS_writev the user buf size is larger than shelter shared buf.\n");
						break;
					}
					if(vec->iov_base)
					{
						memcpy_for_shelter(buf_offset, vec->iov_base, vec->iov_len); 
						uint64_t share_iov_pa = get_phys_from_shelter_virt(share_virt);
						((struct iovec*)share_iov_pa)->iov_base = buf_offset;
						buf_offset += vec->iov_len;
					}
					share_virt += iovec_SIZE;
					iov += iovec_SIZE;
				}	
			}	
		}		
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if(sysno == SYS_sendto || sysno == SYS_recvfrom)
	{
		uint64_t buf = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		size_t len = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		uint64_t addr = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X4);
		int addr_len = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X5);
		task->syscall_shelter_user_addr =  buf;
		task->user_buf_size = len; 
		task->second_syscall_shelter_user_addr = addr;
		task->second_user_buf_size = addr_len;
		if(addr)
		{
			if(sysno == SYS_sendto)
				memcpy_for_shelter(task->task_shared_virt, buf, addr_len);
		}
		if(buf)
		{ 	
			if((task->user_buf_size + SHARE_BUF_OFFSET) > SHELTER_TASK_SHARED_LENGTH)
			{
				NOTICE("syscall_paramater_handle:SYS_sendto/SYS_recvfrom the user buf size is larger than shelter shared buf. The current shelter implementation will tranucate the write buf.\n");
				task->user_buf_size = SHELTER_TASK_SHARED_LENGTH - SHARE_BUF_OFFSET;
				if(sysno == SYS_recvfrom)
					write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2, task->user_buf_size);
			}
			if(sysno == SYS_sendto)
				memcpy_for_shelter(task->task_shared_virt+SHARE_BUF_OFFSET, task->syscall_shelter_user_addr, task->user_buf_size); 
		}
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X4, task->task_shared_virt);
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt+SHARE_BUF_OFFSET);
		task->is_use_task_shared_virt =true;
	}
	else if(sysno == SYS_recvmsg)
	{
		uint64_t user_msg = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		task->syscall_shelter_user_addr = user_msg;
		task->user_buf_size = user_msghdr_SIZE; 
		memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, task->user_buf_size); 
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt);
		uint64_t user_msg_pa = get_phys_from_shelter_virt(user_msg);
		struct user_msghdr* user_msg_content = (struct user_msghdr* )user_msg_pa;
		struct user_msghdr* shared_user_msg_content = (struct user_msghdr* )task->task_shared_phys;
		uint64_t shared_msg_addr = task->task_shared_virt + SHARE_BUF_OFFSET;
		if(user_msg_content->msg_name)
		{
			memcpy_for_shelter(shared_msg_addr, user_msg_content->msg_name, user_msg_content->msg_namelen);
			shared_user_msg_content->msg_name = shared_msg_addr;
			shared_msg_addr += SHARE_BUF_OFFSET;
		}
		if(user_msg_content->msg_iov && user_msg_content->msg_iovlen >0)
		{
			int i;
			struct iovec* vec;
			for(i =0;i<user_msg_content->msg_iovlen;i++)
			{	
				uint64_t iov_pa = get_phys_from_shelter_virt((user_msg_content->msg_iov)[i].iov_base);
				vec = (struct iovec*)iov_pa;
				if((vec->iov_len + shared_msg_addr) > (task->task_shared_virt + SHELTER_TASK_SHARED_LENGTH))
				{
					NOTICE("syscall_paramater_handle:SYS_recvmsg the user buf size is larger than shelter shared buf.\n");
					break;
				}
				uint64_t share_iov_pa = get_phys_from_shelter_virt((shared_user_msg_content->msg_iov)[i].iov_base);
				((struct iovec*)share_iov_pa)->iov_base = shared_msg_addr;
				shared_msg_addr+= vec->iov_len;
			}	
		}		
		task->is_use_task_shared_virt =true;
	}
	else if(sysno == SYS_sendmsg)
	{
		uint64_t user_msg = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		task->syscall_shelter_user_addr = user_msg;
		task->user_buf_size = user_msghdr_SIZE; 
		memcpy_for_shelter(task->task_shared_virt, task->syscall_shelter_user_addr, task->user_buf_size);
		uint64_t user_msg_pa = get_phys_from_shelter_virt(user_msg);
		struct user_msghdr* user_msg_content = (struct user_msghdr* )user_msg_pa;
		struct user_msghdr* shared_user_msg_content = (struct user_msghdr* )task->task_shared_phys;
		uint64_t shared_msg_addr = task->task_shared_virt + SHARE_BUF_OFFSET;
		if(user_msg_content->msg_name)
		{
			memcpy_for_shelter(shared_msg_addr, user_msg_content->msg_name, user_msg_content->msg_namelen);
			shared_user_msg_content->msg_name = shared_msg_addr;
			shared_msg_addr += SHARE_BUF_OFFSET;
		}
		if(user_msg_content->msg_iov && user_msg_content->msg_iovlen >0)
		{
			int i;
			struct iovec vec;
			shared_user_msg_content->msg_iov = (struct iovec *) shared_msg_addr;
			shared_msg_addr += SHARE_BUF_OFFSET;
			struct iovec * user_msg_iov = (struct iovec *) get_phys_from_shelter_virt((uint64_t) user_msg_content->msg_iov);
			struct iovec * shared_msg_iov = (struct iovec *) get_phys_from_shelter_virt((uint64_t) shared_user_msg_content->msg_iov);
			for(i =0;i<user_msg_content->msg_iovlen;i++)
			{	
				vec = user_msg_iov[i];
				if((vec.iov_len + shared_msg_addr) > (task->task_shared_virt + SHELTER_TASK_SHARED_LENGTH))
				{
					NOTICE("syscall_paramater_handle:SYS_sendmsg the user buf size is larger than shelter shared buf.\n");
					break;
				}
				shared_msg_iov[i].iov_base = shared_msg_addr;
				shared_msg_iov[i].iov_len = vec.iov_len;
				if(vec.iov_base)
						memcpy_for_shelter(shared_msg_iov[i].iov_base, vec.iov_base, vec.iov_len);

				shared_msg_addr+= vec.iov_len;
			}	
		}
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if(sysno == SYS_readv)
	{
		unsigned long iov = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		unsigned long iovcnt = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X2);
		task->syscall_shelter_user_addr = iov;
		task->user_buf_size = iovcnt;
		if(task->syscall_shelter_user_addr && iovcnt >0)
		{
			memcpy_for_shelter(task->task_shared_virt, iov, iovcnt*iovec_SIZE);
			uint64_t shared_msg_addr = task->task_shared_virt + SHARE_BUF_OFFSET;
			int i;			
			struct iovec* vec = (struct iovec*)get_phys_from_shelter_virt(iov);
			struct iovec* shared_vec = (struct iovec*)task->task_shared_phys;
			for(i = 0; i < iovcnt; i++)
			{	
				if((vec[i].iov_len + shared_msg_addr) > (task->task_shared_virt + SHELTER_TASK_SHARED_LENGTH))
				{
					NOTICE("syscall_paramater_handle: the user buf size is larger than shelter shared buf.\n");
					break;
				}
				shared_vec[i].iov_base = shared_msg_addr;
				shared_msg_addr+= vec[i].iov_len;
			}	
		}		
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->task_shared_virt);
		task->is_use_task_shared_virt =true;
	}
	else if (sysno == SYS_getrandom)
	{
		task->syscall_shelter_user_addr =  read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
		task->user_buf_size = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1);
		if(task->user_buf_size > SHELTER_TASK_SHARED_LENGTH)
		{
			NOTICE("syscall_paramater_handle:SYS_getrandom the user buf size is larger than shelter shared buf. We will truncate the size.\n");
			task->user_buf_size = SHELTER_TASK_SHARED_LENGTH;
		}
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0, task->task_shared_virt);
		write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X1, task->user_buf_size);
		task->is_use_task_shared_virt =true;
	}
	if(task->is_use_task_shared_virt)
	{
		gpt_transition_pas_mul_enc(0 ,task->task_shared_phys, task->task_shared_length, GPI_NS);
	}
	else if (task->is_use_task_signal_stack_virt)
	{
		gpt_transition_pas_mul_enc(0 ,task->task_signal_stack_phys, task->task_signal_stack_length, GPI_NS);
	}
	else if(task->is_use_task_futex_virt)
	{
		gpt_transition_pas_mul_enc(0, task->task_futex_phys, FUTEX_PAGE, GPI_NS);
	}
out:;
	gpt_enable_enc(0);
}

/**** SHELTER lifecycle management ****/

//ENC_NEW_TEST---shelter_creation used by shelter_exec
//x1 =  enclave memory phsy address
//x2 =  EL0 stack sp
//x3 =  EL0 enclave entry
//x4 =  shelter fd
//x5 =  EL1 enc_vector virt address
//x6 = 	ENC size
//x7 =  task_struct_addr
int shelter_creation(u_register_t arg1, u_register_t arg2, u_register_t arg3, u_register_t arg4, u_register_t arg5, u_register_t arg6, u_register_t arg7)
{	
	spin_lock(&gpt_lock2);
	/* Save incoming state */
	cm_el1_sysregs_context_save(NON_SECURE);
	cpu_context_t *src_ctx = cm_get_context(NON_SECURE);
	
	uint64_t vector_pa = get_phys_from_shelter_virt(arg5);
	if(!shelters_gpt_memory_overlap_check(arg1, arg6) || !shelters_gpt_memory_overlap_check(vector_pa, EXCEPTION_VECTOR_LENGTH))
	{
		NOTICE("shelters_gpt_memory_overlap\n");
		return -1;
	}

	int ret = shelter_verify_sign(vector_pa, EXCEPTION_VECTOR_LENGTH);
	if(ret != 1)
	{
		NOTICE("sign fault\n");
		return -1;
	}
		

	size_t enc_id = build_enc_gpt();


	gpt_mem[enc_id].enc_phys_pa1 = arg1;
	gpt_mem[enc_id].enc_phys_size1 = arg6;
	gpt_mem[enc_id].fd_cma = arg4;
	NOTICE("shelter fd: %d\n",gpt_mem[enc_id].fd_cma);
	gpt_mem[enc_id].shelter_vector_virt_addr = arg5;
	gpt_mem[enc_id].enc_phys_pa2 = vector_pa;
	gpt_mem[enc_id].enc_phys_size2 = SHELTER_VECTOR_PAGE_TABLE_SPACE;
	gpt_mem[enc_id].os_vector_virt_addr = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_VBAR_EL1);


	//init the shelter task
	size_t task_id = search_empty_task();
	shelter_tasks[task_id].enc_id = enc_id;
	shelter_tasks[task_id].enc_sp = arg2;
	shelter_tasks[task_id].task_elr_el1 = arg3;
	shelter_tasks[task_id].os_TTBR0_EL1 = (read_ttbr0_el1()& (~0x1)); 
	shelter_tasks[task_id].task_struct_addr = arg7;
	shelter_tasks[task_id].tid = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_CONTEXTIDR_EL1);
	shelter_tasks[task_id].inited = true;
	
	if(enc_id == 1){	
		memcpy((void *)(ARM_PAS_L1_GPT_BASE), (void *)(ARM_PAS_L1_GPT_BASE + ARM_L1_GPT_SIZE), ARM_L1_GPT_SIZE);
	}

	gpt_mem[enc_id].alive = true;
	//protect shelter memory regions
	transition_enc_pas(enc_id ,gpt_mem[enc_id].enc_phys_pa1, gpt_mem[enc_id].enc_phys_size1);
	transition_enc_pas(enc_id ,gpt_mem[enc_id].enc_phys_pa2, gpt_mem[enc_id].enc_phys_size2);

	//copy page table from OS to shelter's memory. Thus shelter's page table cannot be modified by OS
	shelter_tasks[task_id].sapp_TTBR0_EL1 = allocate_shelter_page_table(enc_id, shelter_tasks[task_id].os_TTBR0_EL1);
	if(shelter_tasks[task_id].sapp_TTBR0_EL1 == 0)
	{
		 NOTICE("copy page table fault\n");
	}
	
	gpt_enable_enc(0);
	cm_el1_sysregs_context_restore(NON_SECURE);
	spin_unlock(&gpt_lock2);
	return enc_id;
}

//ENC_ENTER---enter shelter 
/*In this state invoked from kernel exit of OS, the shelter_task
has inited, so we can use the shelter_task to check potential risks and the SApp
cannot be executed without switching its GPT. For a legal new thread or process, we
have built the shelter_task by invoking shelter_clone.*/
u_register_t shelter_enter(u_register_t arg1, u_register_t arg2, u_register_t arg3)
{	
	spin_lock(&gpt_lock2);
	
	cm_el1_sysregs_context_save(NON_SECURE);
	cpu_context_t *src_ctx  = cm_get_context(NON_SECURE);
	u_register_t task_struct = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X14);
	uint64_t tid = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_CONTEXTIDR_EL1);
	size_t task_id = search_shelter_task(task_struct, tid);
	if (task_id == 0xFF)
	{	
		NOTICE("Fail to find task_struct in shelter_tasks\n");
		panic();
	}
	size_t enc_id = shelter_tasks[task_id].enc_id;
	gpt_enable_enc(enc_id);
	u_register_t TTBR0_EL1 = read_ttbr0_el1();
	if(shelter_tasks[task_id].os_TTBR0_EL1 == 0)
	{	
		shelter_tasks[task_id].os_TTBR0_EL1 = TTBR0_EL1& (~0x1);
		NOTICE("tid:%llu, a new process shelter task's ttbr0 is 0x%llx\n", shelter_tasks[task_id].tid, shelter_tasks[task_id].os_TTBR0_EL1);
	}
	else if((TTBR0_EL1& (~0x1)) != shelter_tasks[task_id].os_TTBR0_EL1)
	{	
		NOTICE("tid:%llu, The shelter task's ttbr0 has been changed to 0x%lx\n", shelter_tasks[task_id].tid, TTBR0_EL1);
		shelter_tasks[task_id].os_TTBR0_EL1 = TTBR0_EL1;
	}
	u_register_t x0 = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X13);
	write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0, x0);

	/***
	Iago attack checks: 
	i) we do simple checks on system call return values in our handled syscall to ensure they fall
	within predefined correct ranges. e.g., the return len will be checked with the valided buffer size paramater. 
	
	ii) To keep shelter's TCB simple and small, we protects against memory-based Iago attacks
	via maintaining shelter's page table and checking the memory allocation overlap whenever a new page mapping happend.
	(allocate_shelter_page_table, shelters_gpt_memory_overlap_check, allocate_memory_check)
	
	***/
	if(shelter_tasks[task_id].is_wait_syscall_ret)
	{	
		shelter_syscall_result_handle(&shelter_tasks[task_id], src_ctx);
		shelter_tasks[task_id].is_wait_syscall_ret = false;
		shelter_tasks[task_id].wait_syscallno = 0;
	}

	else if(shelter_tasks[task_id].is_wait_data_abort_ret)
	{	
		if(shelter_tasks[task_id].wait_data_abort_exception == 0x9200004f)
		{
			shelter_set_page(tid, shelter_tasks[task_id].far_addr, S_PAGE_SIZE, 0);
			gpt_enable_enc(enc_id);
		}
		shelter_tasks[task_id].is_wait_data_abort_ret = false;
		shelter_tasks[task_id].wait_data_abort_exception = 0;
	}

	u_register_t pc = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_ELR_EL1);
	// Maybe the signal handler is being handled if the pc is inconsistent
	if(pc != shelter_tasks[task_id].task_elr_el1 && shelter_tasks[task_id].task_elr_el1!=0)
	{	
		NOTICE("tid:%llu, The shelter's return address is inconsistent. pc = 0x%lx, task_elr_el1=0x%llx\n", shelter_tasks[task_id].tid, pc, shelter_tasks[task_id].task_elr_el1);
		if(pc == (shelter_tasks[task_id].task_elr_el1 + 0x4))
		{
			shelter_tasks[task_id].task_elr_el1 = pc;
			goto out;
		}
		// verify that the address has been registered to ensure that the task will be correctly returning to a registered handler
		if(!search_registered_signal_handler(task_id,pc))
		{
			NOTICE("tid:%llu, The shelter's return address is not a registered signal handler address.\n", shelter_tasks[task_id].tid);
			panic();
		}
		// make the signal stack memory inaccessible to the OS before the signal handler is executed
		gpt_transition_pas_mul_enc(0, shelter_tasks[task_id].task_signal_stack_phys, shelter_tasks[task_id].task_signal_stack_length, GPI_ROOT);
		// record the pc for checking in later sigreturn 
		shelter_tasks[task_id].ret_pc_from_signal = shelter_tasks[task_id].task_elr_el1;
		shelter_tasks[task_id].task_elr_el1 = pc;
		
	}	
out:;
	//use shelter page table and diable cnp bit to defense gpt tlb attack
	write_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_TTBR0_EL1, shelter_tasks[task_id].sapp_TTBR0_EL1 & (~0x1));

	shelter_tasks[task_id].task_sp_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_SP_EL1);
	write_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_VBAR_EL1, gpt_mem[enc_id].shelter_vector_virt_addr);
	x0 = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
	u_register_t spsr_el3 = SPSR_64(MODE_EL0, MODE_SP_EL0, 0);
	cm_set_elr_spsr_el3(NON_SECURE, pc, spsr_el3);
	cm_el1_sysregs_context_restore(NON_SECURE);
	cm_set_next_eret_context(NON_SECURE);
	spin_unlock(&gpt_lock2);
	return x0;
}

/**** SHELTER exception handler ****/
uint64_t exception_request_os(
	u_register_t x1,
	u_register_t x2,
	u_register_t x3,
	u_register_t x4)
{	
	spin_lock(&gpt_lock2);
	cm_el1_sysregs_context_save(NON_SECURE);
	cpu_context_t *src_ctx  = cm_get_context(NON_SECURE);
	uint64_t tid = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_CONTEXTIDR_EL1);
	size_t task_id = search_shelter_task(0, tid);
	if (task_id == 0xFF)
	{	
		NOTICE("Fail to find task_struct in shelter_tasks\n");
		panic();
	}
	size_t enc_id = shelter_tasks[task_id].enc_id;
	u_register_t esr_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_ESR_EL1);
	u_register_t vector_handler_offset = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X14);
	u_register_t x0 = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X13);
	write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0, x0);
	if (esr_el1 == 0x56000000 && vector_handler_offset ==0)
	{
		uint32_t syscallno = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X8);
		shelter_tasks[task_id].wait_syscallno = syscallno;
		shelter_tasks[task_id].is_wait_syscall_ret = true;

		NOTICE("task_id:%lu, tid:%llu, syscall no 0x%x\n", task_id, shelter_tasks[task_id].tid, syscallno);

		//identify and replace some syscall's parameter pointing shelter's user
		//space to the shared buffer address, shelter's gpt is switched in the function
		syscall_paramater_handle(&shelter_tasks[task_id], syscallno);
	}
	else
	{	
		if(vector_handler_offset ==0)
		{
			if(esr_el1 & 0x92000000)
			{
				u_register_t far_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_FAR_EL1);
				u_register_t elr_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_ELR_EL1);
				NOTICE("exception_request_os task_id:%lu, tid:%llu, esr_el1 0x%lx, far_el1: 0x%lx, elr_el1: 0x%lx\n", task_id, shelter_tasks[task_id].tid, esr_el1, far_el1, elr_el1);
				shelter_tasks[task_id].wait_data_abort_exception = esr_el1;
				shelter_tasks[task_id].is_wait_data_abort_ret = true;	
				shelter_tasks[task_id].far_addr = far_el1;
			}
		}
		gpt_enable_enc(0);
	}
	// set the eret to be the linux vector entry and let OS change the original os_TTBR0_EL1 user page table
	write_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_TTBR0_EL1, shelter_tasks[task_id].os_TTBR0_EL1 & (~0x1));
	write_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_VBAR_EL1, gpt_mem[enc_id].os_vector_virt_addr);
	write_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_SP_EL1, shelter_tasks[task_id].task_sp_el1);
	x0 = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);
	//save the valid return address
	shelter_tasks[task_id].task_elr_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_ELR_EL1);
	u_register_t pc = gpt_mem[enc_id].os_vector_virt_addr + VECTOR_EL0_OFFSET + vector_handler_offset;
	u_register_t spsr_el3 = SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_INTERRUPTS);
	cm_set_elr_spsr_el3(NON_SECURE, pc, spsr_el3);
	cm_el1_sysregs_context_restore(NON_SECURE);
	cm_set_next_eret_context(NON_SECURE);
	// gpt_disable();
	spin_unlock(&gpt_lock2);
	return x0;
}

/**** SHELTER Clone ****/
int shelter_clone(u_register_t x1, u_register_t x2, u_register_t x3, u_register_t x4, u_register_t x5, u_register_t x6, u_register_t x7)
{	
	u_register_t task_struct = x1;
	uint64_t calling_tid = x2;
	uint64_t tid = x3;
	int is_fork_flag = x4;
	NOTICE("shelter clone--task_struct_addr:0x%lx, ppid:%llu, tid:%llu\n", task_struct, calling_tid, tid);

	if(calling_tid == tid)
	{
		NOTICE("The calling task has invalid tid\n");
		panic();
	}
	size_t parent_task_id = search_shelter_task(0, calling_tid);
	if (parent_task_id == 0xFF)
	{	
		NOTICE("Fail to find task_struct in shelter_tasks, the calling task is fault\n");
		panic();
	}
	size_t task_id = search_empty_task();
	shelter_tasks[task_id].task_struct_addr = task_struct;
	shelter_tasks[task_id].tid = tid;
	shelter_tasks[task_id].inited = true;

	//sync the thread's shared task vals.
	if(!is_fork_flag)
	{
		shelter_tasks[task_id].enc_id = shelter_tasks[parent_task_id].enc_id; 
		shelter_tasks[task_id].os_TTBR0_EL1= shelter_tasks[parent_task_id].os_TTBR0_EL1;
		shelter_tasks[task_id].sapp_TTBR0_EL1= shelter_tasks[parent_task_id].sapp_TTBR0_EL1;
	}
	return 0;
}

/**** expand shelter memory pool for the SApp ****/
int shelter_memexpand(u_register_t x1, u_register_t x2, u_register_t x3, u_register_t x4)
{	
	cm_el1_sysregs_context_save(NON_SECURE);
	cpu_context_t *src_ctx  = cm_get_context(NON_SECURE);
	uint64_t tid = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_CONTEXTIDR_EL1);
	size_t task_id = search_shelter_task(0, tid);
	if (task_id == 0xFF)
	{	
		NOTICE("Fail to find task_struct in shelter_tasks\n");
		panic();
	}
	if(!shelters_gpt_memory_overlap_check(x1, x2))
	{
		NOTICE("shelters_gpt_memory_overlap!\n");
		return -1;
	}
	size_t enc_id = shelter_tasks[task_id].enc_id;
	spin_lock(&gpt_lock2);
	if(gpt_mem[enc_id].enc_phys_pa3 ==0)
	{
		gpt_mem[enc_id].enc_phys_pa3 = x1;
		gpt_mem[enc_id].enc_phys_size3 = x2;
		transition_enc_pas(enc_id ,gpt_mem[enc_id].enc_phys_pa3, gpt_mem[enc_id].enc_phys_size3);
	}
	else if(gpt_mem[enc_id].enc_phys_pa4 ==0)
	{
		gpt_mem[enc_id].enc_phys_pa4 = x1;
		gpt_mem[enc_id].enc_phys_size4 = x2;
		transition_enc_pas(enc_id ,gpt_mem[enc_id].enc_phys_pa4, gpt_mem[enc_id].enc_phys_size4);
	}
	else{
		NOTICE("Fail to expand shelter memory, the standby enc_phys_pa is full.\n");
		spin_unlock(&gpt_lock2);
		return -1;
	}
	gpt_mem[enc_id].enc_pg.use_mem_pool = true;
	spin_unlock(&gpt_lock2);
	return 0;
}

/**** SHELTER Task exit ****/
int shelter_task_exit(u_register_t arg1, u_register_t arg2, u_register_t arg3)
{	
	spin_lock(&gpt_lock2);
	u_register_t task_struct = arg1;
	uint64_t tid = arg2;
	size_t task_id = search_shelter_task(task_struct, tid);
	if (task_id == 0xFF)
	{	
		NOTICE("Fail to find task_struct in shelter_tasks in shelter_task_exit\n");
		panic();
	}
	NOTICE("task_exit--task_id:%lu, tid:%llu\n", task_id, shelter_tasks[task_id].tid);
	
	if(shelter_tasks[task_id].inited)
	{
		memset(&shelter_tasks[task_id], 0, sizeof(shelter_task_t));
	}
	spin_unlock(&gpt_lock2);
	return 0;
}

//ENC_DESTROY_TEST
int shelter_destruct(u_register_t arg1, u_register_t arg2, u_register_t arg3)
{
	spin_lock(&gpt_lock2);
	u_register_t task_struct = arg1;
	uint64_t tid = arg2;
	size_t task_id = search_shelter_task(task_struct, tid);
	if (task_id == 0xFF)
	{	
		NOTICE("Fail to find task_struct in shelter_tasks in shelter_destruct\n");
		panic();
	}
	NOTICE("shelter_destruct--task_id:%lu, tid:%llu\n", task_id, shelter_tasks[task_id].tid);
	size_t enc_id = shelter_tasks[task_id].enc_id;
	if(!gpt_mem[enc_id].alive)
		goto out;
	
	gpt_enable_enc(enc_id);
	if(gpt_mem[enc_id].enc_phys_pa1!=0)
	{	
		memset((void *)gpt_mem[enc_id].enc_phys_pa1, gpt_mem[enc_id].enc_phys_size1, 0);
		gpt_clean_dcache_range(gpt_mem[enc_id].enc_phys_pa1, gpt_mem[enc_id].enc_phys_size1);
		gpt_transition_pas_mul_enc_all(gpt_mem[enc_id].enc_phys_pa1, gpt_mem[enc_id].enc_phys_size1, GPI_NS);
	}
	if(gpt_mem[enc_id].enc_phys_pa2!=0)
	{	
		memset((void *)gpt_mem[enc_id].enc_phys_pa2, gpt_mem[enc_id].enc_phys_size2, 0);
		gpt_clean_dcache_range(gpt_mem[enc_id].enc_phys_pa2, gpt_mem[enc_id].enc_phys_size2);
		gpt_transition_pas_mul_enc_all(gpt_mem[enc_id].enc_phys_pa2, gpt_mem[enc_id].enc_phys_size2, GPI_NS);
	}
	if(gpt_mem[enc_id].enc_phys_pa3!=0)
	{	
		memset((void *)gpt_mem[enc_id].enc_phys_pa3, gpt_mem[enc_id].enc_phys_size3, 0);
		gpt_clean_dcache_range(gpt_mem[enc_id].enc_phys_pa3, gpt_mem[enc_id].enc_phys_size3);
		gpt_transition_pas_mul_enc_all(gpt_mem[enc_id].enc_phys_pa3, gpt_mem[enc_id].enc_phys_size3, GPI_NS);
	}
	if(gpt_mem[enc_id].enc_phys_pa4!=0)
	{	
		memset((void *)gpt_mem[enc_id].enc_phys_pa4, gpt_mem[enc_id].enc_phys_size4, 0);
		gpt_clean_dcache_range(gpt_mem[enc_id].enc_phys_pa4, gpt_mem[enc_id].enc_phys_size4);
		gpt_transition_pas_mul_enc_all(gpt_mem[enc_id].enc_phys_pa4, gpt_mem[enc_id].enc_phys_size4, GPI_NS);
	}

	memset(&gpt_mem[enc_id], 0, sizeof(gpt_mem_t));	
	gpt_enable_enc(0);
	tlbipaallos();	
out:;	
	spin_unlock(&gpt_lock2);
	return 0;
}

//assign share buffer, etc. Those memory are from CMA memory
int enc_nc_ns(u_register_t x1, u_register_t x2, u_register_t x3, u_register_t x4)
{	
	spin_lock(&gpt_lock2);
	
	uint64_t tid = x1;
	size_t task_id = search_shelter_task(0, tid);
	if (task_id == 0xFF)
	{	
		NOTICE("Fail to find task_struct in shelter_tasks in enc_nc_ns\n");
		panic();
	}

	uint64_t pa;

	if(x2 !=0)
	{
		pa = get_phys_from_shelter_virt(x2);
		if(pa == 0 || !allocate_memory_check(pa,SHELTER_TASK_SHARED_LENGTH, shelter_tasks[task_id].enc_id))
		{
			NOTICE("error in task_shared_virt enc_nc_ns\n");
			panic();
		}
		shelter_tasks[task_id].task_shared_virt = x2;
		shelter_tasks[task_id].task_shared_length = SHELTER_TASK_SHARED_LENGTH;
		shelter_tasks[task_id].task_shared_phys = pa; 
	}
	if(x3 !=0)
	{
		pa = get_phys_from_shelter_virt(x3);
		if(pa == 0 || !allocate_memory_check(pa,SHELTER_TASK_SIGNAL_STACK_LENGTH, shelter_tasks[task_id].enc_id))
		{
			NOTICE("error in task_signal_stack_virt enc_nc_ns\n");
			panic();
		}
		shelter_tasks[task_id].task_signal_stack_virt = x3;
		shelter_tasks[task_id].task_signal_stack_length = SHELTER_TASK_SIGNAL_STACK_LENGTH;
		shelter_tasks[task_id].task_signal_stack_phys = pa;
		//make the signal frame stack accessible for OS to remedy for later setup_frame.
		gpt_transition_pas_mul_enc(0 ,shelter_tasks[task_id].task_signal_stack_phys, shelter_tasks[task_id].task_signal_stack_length, GPI_NS);

	}
	spin_unlock(&gpt_lock2);
	return 0;
}
