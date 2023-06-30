/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef GPT_H
#define GPT_H

#include <stdint.h>

#include <arch.h>
#include <errno.h>
#include <lib/spinlock.h>

#include "gpt_defs.h"

#define GPT_DESC_ATTRS(_type, _gpi)		\
	((((_type) & PAS_REG_DESC_TYPE_MASK)	\
	  << PAS_REG_DESC_TYPE_SHIFT) |		\
	(((_gpi) & PAS_REG_GPI_MASK)		\
	 << PAS_REG_GPI_SHIFT))

/*
 * Macro to create a GPT entry for this PAS range either as a L0 block
 * descriptor or L1 table descriptor depending upon the size of the range.
 */
#define MAP_GPT_REGION(_pa, _sz, _gpi)					\
	{								\
		.base_pa = (_pa),					\
		.size = (_sz),						\
		.attrs = GPT_DESC_ATTRS(PAS_REG_DESC_TYPE_ANY, (_gpi)),	\
	}

/*
 * Special macro to create a L1 table descriptor at L0 for a 1GB region as
 * opposed to creating a block mapping by default.
 */
#define MAP_GPT_REGION_TBL(_pa, _sz, _gpi)				\
	{								\
		.base_pa = (_pa),					\
		.size = (_sz),						\
		.attrs = GPT_DESC_ATTRS(PAS_REG_DESC_TYPE_TBL, (_gpi)),	\
	}

/*
 * Structure for specifying a Granule range and its properties
 */
typedef struct pas_region {
	unsigned long long	base_pa;	/**< Base address for PAS. */
	size_t			size;		/**< Size of the PAS. */
	unsigned int		attrs;		/**< PAS GPI and entry type. */
} pas_region_t;

/*
 * Structure to initialise the Granule Protection Tables.
 */
typedef struct gpt_init_params {
	unsigned int pgs;	/**< Address Width of Phisical Granule Size. */
	unsigned int pps;	/**< Protected Physical Address Size.	     */
	unsigned int l0gptsz;	/**< Granule size on L0 table entry.	     */
	pas_region_t *pas_regions; /**< PAS regions to protect.		     */
	unsigned int pas_count;	/**< Number of PAS regions to initialise.    */
	uintptr_t l0_mem_base;	/**< L0 Table base address.		     */
	size_t l0_mem_size;	/**< Size of memory reserved for L0 tables.  */
	uintptr_t l1_mem_base;	/**< L1 Table base address.		     */
	size_t l1_mem_size;	/**< Size of memory reserved for L1 tables.  */
} gpt_init_params_t;

/** @brief Initialise the Granule Protection tables.
 */
int gpt_init(gpt_init_params_t *params);

/** @brief Enable the Granule Protection Checks.
 */
void gpt_enable(void);

/** @brief Disable the Granule Protection Checks.
 */
void gpt_disable(void);

/** @brief Transition a granule between security states.
 */
int gpt_transition_pas_enc(size_t enc_id, uint64_t pa,
			unsigned int target_pas);

int gpt_transition_pas_mul_enc(size_t enc_id, uint64_t pa, uint64_t size,
			unsigned int target_pas);

int gpt_transition_pas_mul_enc_all(uint64_t pa, uint64_t size,
			unsigned int target_pas);

int transition_enc_pas(size_t enc_id, uint64_t pa, uint64_t size);

int gpt_transition_pas(uint64_t pa,
			unsigned int src_sec_state,
			unsigned int target_pas);

//Test enclave
int shelter_creation(u_register_t arg1, u_register_t arg2, u_register_t arg3, u_register_t arg4, u_register_t arg5, u_register_t arg6, u_register_t arg7);
int shelter_task_exit(u_register_t arg1, u_register_t arg2, u_register_t arg3);
int shelter_set_page(u_register_t x1,
	u_register_t x2,
	u_register_t x3,
	u_register_t x4);

uint64_t exception_request_os(
	u_register_t x1,
	u_register_t x2,
	u_register_t x3,
	u_register_t x4);


int verify_sign(u_register_t base, u_register_t size);

int shelter_destruct(u_register_t arg1, u_register_t arg2, u_register_t arg3);
u_register_t shelter_enter(u_register_t arg1, u_register_t arg2, u_register_t arg3);

int enc_nc_ns(
	u_register_t x1,
	u_register_t x2,
	u_register_t x3,
	u_register_t x4);

int shelter_memexpand(
	u_register_t x1,
	u_register_t x2,
	u_register_t x3,
	u_register_t x4);

int shelter_clone(u_register_t x1, u_register_t x2, u_register_t x3, u_register_t x4, u_register_t x5, u_register_t x6, u_register_t x7);

#define VECTOR_EL0_OFFSET 0x400
#define SHARE_BUF_OFFSET 0x1000
#define FUTEX_PAGE 0x1000

//3-level page table
typedef struct {
	uint64_t enc_pgd_phys_addr;
	uint64_t enc_pmd_phys_addr;
	uint64_t enc_pte_phys_addr;
	uint32_t enc_pmd_pages_number;
	uint32_t enc_pte_pages_number;
	uint32_t pmd_pages_index;
	uint32_t pte_pages_index;
	uint64_t pg_length;
	uint64_t enc_id;
	bool use_mem_pool;
} shelter_pg;
static spinlock_t pgd_lock;
static spinlock_t pmd_lock;
#define PGDIR_SIZE 0x40000000
#define PGDIR_SHIFT 30
#define PTRS_PER_PGD 512
#define PGDIR_MASK		(~(PGDIR_SIZE-1))
#define PMD_SIZE 0x200000
#define PMD_SHIFT 21
#define PTRS_PER_PMD 512
#define PMD_MASK		(~(PMD_SIZE-1))
#define S_PAGE_SIZE 0x1000
#define PAGE_SHIFT 12
#define PTRS_PER_PTE 512
#define VA_END 0x7fffffffff

typedef unsigned long pteval_t;
typedef unsigned long pmdval_t;
typedef unsigned long pudval_t;
typedef unsigned long pgdval_t;

#define pgd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})


#ifndef pmd_addr_end
#define pmd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PMD_SIZE) & PMD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#endif


#define pgd_index(addr)		(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pgd_offset_raw(pgd, addr)	((pgd) + pgd_index(addr))
typedef struct { pgdval_t pgd; } pgd_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pteval_t pte; } pte_t;
#define pgd_val(x)	((x).pgd)
#define __pgd(x)	((pgd_t) { (x) } )
#define pgd_none(pgd)		(!pgd_val(pgd))
#define pgd_bad(pgd)		(!(pgd_val(pgd) & 2))
#define pgd_present(pgd)	(pgd_val(pgd))
#define PUD_TYPE_TABLE		UL(3<<0)
#define PMD_TABLE_BIT		UL(1<<1)
#define PMD_TYPE_TABLE		UL(3<<0)
#define pmd_val(x)	((x).pmd)
#define __pmd(x)	((pmd_t) { (x) } )
#define pmd_none(pmd)		(!pmd_val(pmd))
#define pmd_index(addr)		(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pmd_bad(pmd)		(!(pmd_val(pmd) & PMD_TABLE_BIT))
#define pmd_present(pmd)	(pmd_val(pmd))
#define pte_index(addr)		(((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_val(x)	((x).pte)
#define __pte(x)	((pte_t) { (x) } )
#define pte_none(pte)		(!pte_val(pte))


static inline int pgd_none_or_clear_bad(pgd_t *pgd)
{
	if (pgd_none(*pgd))
		return 1;
	if ((pgd_bad(*pgd))) {
		return 1;
	}
	return 0;
}

static inline int pmd_none_or_clear_bad(pmd_t *pmd)
{
	if (pmd_none(*pmd))
		return 1;
	if ((pmd_bad(*pmd))) {
		return 1;
	}
	return 0;
}


static inline pmd_t* pmd_offset(pgd_t *pgd, unsigned long address)
{
	pgdval_t pmd_addr = pgd_val(*pgd) & (0xFFFFFFFFF000);
	return (pmd_t *)(pmd_addr + pmd_index(address) * sizeof(pmd_t));
}

static inline pte_t* pte_offset(pmd_t *pmd, unsigned long address)
{
	pgdval_t pte_addr = pmd_val(*pmd) & (0xFFFFFFFFF000);
	return (pte_t *)(pte_addr + pte_index(address) * sizeof(pte_t));
}

static inline pmd_t *pmd_alloc_one(shelter_pg * enc_pg, unsigned long addr)
{
	uint64_t page = 0;
	if(enc_pg->pmd_pages_index< enc_pg->enc_pmd_pages_number)
	{
		page = enc_pg->enc_pmd_phys_addr + S_PAGE_SIZE * enc_pg->pmd_pages_index;
		enc_pg->pmd_pages_index += 1;
	}
	if (!page)
		return NULL;
	return (pmd_t *)page;
}

static inline pte_t *pte_alloc_one(shelter_pg * enc_pg, unsigned long addr)
{
	uint64_t page = 0;
	if(enc_pg->pte_pages_index< enc_pg->enc_pte_pages_number)
	{
		page = enc_pg->enc_pte_phys_addr + S_PAGE_SIZE * enc_pg->pte_pages_index;
		enc_pg->pte_pages_index += 1;
	}
	if (!page)
		return NULL;
	return (pte_t *)page;
}

static inline void pmd_free(shelter_pg * enc_pg, pmd_t *pmd)
{
	if(enc_pg->pmd_pages_index>0)
	{
		memset((void*) pmd, 0, S_PAGE_SIZE);
		enc_pg->pmd_pages_index -= 1;
	}
}

static inline void pte_free(shelter_pg * enc_pg, pte_t *pte)
{
	if(enc_pg->pte_pages_index>0)
	{
		memset((void*) pte, 0, S_PAGE_SIZE);
		enc_pg->pte_pages_index -= 1;
	}
}

static inline void __pgd_populate(pgd_t *pgdp, uint64_t pudp, pgdval_t prot)
{
	*pgdp = __pgd(pudp| prot);
}

static inline void pgd_populate(shelter_pg * enc_pg, pgd_t *pgdp, pmd_t *pudp)
{
	__pgd_populate(pgdp, (uint64_t)pudp, PUD_TYPE_TABLE);
}

static inline void __pmd_populate(pmd_t *pmdp, uint64_t ptep, pgdval_t prot)
{
	*pmdp = __pmd(ptep| prot);
}

static inline void pmd_populate(shelter_pg * enc_pg, pmd_t *pmdp, pte_t *ptep)
{
	__pmd_populate(pmdp, (uint64_t)ptep, PMD_TYPE_TABLE);
}

static inline int __pmd_alloc(shelter_pg * enc_pg, pgd_t *pud, unsigned long address)
{
	pmd_t *new = pmd_alloc_one(enc_pg, address);
	if (!new)
		return -ENOMEM;
	spin_lock(&pgd_lock);
	if (!pgd_present(*pud)) {
		pgd_populate(enc_pg, pud, new);
	} else /* Another has populated it */
		pmd_free(enc_pg, new);
	spin_unlock(&pgd_lock);
	return 0;
}

static inline int __pte_alloc(shelter_pg * enc_pg, pmd_t *pmd, unsigned long address)
{
	pte_t *new = pte_alloc_one(enc_pg, address);
	if (!new)
		return -ENOMEM;
	spin_lock(&pmd_lock);
	if (!pmd_present(*pmd)) {
		pmd_populate(enc_pg, pmd, new);
	} else
		pte_free(enc_pg, new);
	spin_unlock(&pmd_lock);
	return 0;
}

static inline pmd_t *pmd_alloc(shelter_pg * enc_pg, pgd_t *pgd, unsigned long address)
{
	return (pgd_none(*pgd) && __pmd_alloc(enc_pg, pgd, address))?
		NULL: pmd_offset(pgd, address);
}

static inline pte_t *pte_alloc(shelter_pg * enc_pg, pmd_t *pmd, unsigned long address)
{
	return (pmd_none(*pmd) && __pte_alloc(enc_pg, pmd, address))?
		NULL: pte_offset(pmd, address);
}


//syscall required to be compatible
#define SYS_FSTAT 0x50
#define SYS_IOCTL 0x1d
#define SYS_READ 0x3f
#define SYS_WRITE 0x40
#define SYS_UNAME 0xa0
#define SYS_READLINKAT 0x4e
#define SYS_OPENAT 0x38
#define SYS_RT_SIGACTION 0x86
#define SYS_RT_SIGPROCMASK 0x87
#define SYS_RT_SIGRETURN 0x8b
#define SYS_FUTEX 0x62
#define SYS_clone 0xdc
#define SYS_PRLIMIT64 0x105
#define SYS_GETRLIMIT 0xa3
#define SYS_CONNECT 0xcb
#define SYS_clock_gettime 0x71
#define SYS_gettimeofday 0xa9
#define SYS_MUNMAP 0xd7
#define SYS_epoll_ctl 0x15
#define SYS_bind 0xc8
#define SYS_setsockopt 0xd0
#define SYS_nanosleep 0x65
#define SYS_getsockname 0xcc
#define SYS_getpeername 0xcd
#define SYS_accept 0xca
#define SYS_accept4 0xf2
#define SYS_socketpair 0xc7
#define SYS_newfstatat 0x4f
#define SYS_pwrite64 0x44
#define SYS_pread64 0x43
#define SYS_epoll_pwait 0x16
#define SYS_writev 0x42
#define SYS_sendfile 0x47
#define SYS_sendto 0xce
#define SYS_recvfrom 0xcf
#define SYS_sendmsg 0xd3
#define SYS_recvmsg 0xd4
#define SYS_readv 0x41
#define SYS_getrandom 0x116
#define SYS_sysinfo 0xb3
#define SYS_pselect6 0x48
#define SYS_ppoll	0x49
#define SYS_pipe2	0x3b
#define SYS_unlinkat 0x23
#define SYS_fchmodat 0x35
#define SYS_mkdirat 0x22
#define SYS_renameat 0x26
#define SYS_renameat2 0x114
#define SYS_setgroups 0x9f


//syscall struct
#define UTSNAME_SIZE 325
#define STAT_SIZE 128
#define TERMIOX_SIZE 16
#define TERMIO_SIZE 18
#define TERMIOS_SIZE 36
#define TERMIOS2_SIZE 44
#define KTERMIOS_SIZE 44
#define SIGACTION_SIZE 32
#define SIGSET_SIZE 8
#define RLIMIT64_SIZE 16
#define RLIMIT_SIZE 16
#define FUTEX_SIZE 4
#define __kernel_timespec_SIZE 16
#define timeval_SIZE 16
#define timezone_SIZE 8
#define epoll_event_SIZE 16
#define sockaddr_SIZE 16
#define user_msghdr_SIZE 56
#define fiemap_SIZE 32
#define file_clone_range_SIZE 32
#define space_resv_SIZE 48
#define iovec_SIZE 16
#define sysinfo_SIZE 112
#define fd_set_SIZE 128
#define pollfd_SIZE 8
#define FDS_BITPERLONG	(8*sizeof(long))
#define FDS_LONGS(nr)	(((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define FDS_BYTES(nr)	(FDS_LONGS(nr)*sizeof(long))

struct sigaction {
	uint64_t	sa_handler;
};	

struct iovec
{
	uint64_t iov_base;	
	unsigned long iov_len; 
};

struct user_msghdr {
	uint64_t		 msg_name;	/* ptr to socket address structure */
	int		msg_namelen;		/* size of socket address structure */
	struct iovec	 *msg_iov;	/* scatter/gather array */
	unsigned long	msg_iovlen;		/* # elements in msg_iov */
	uint64_t		msg_control;	/* ancillary data */
	unsigned long	msg_controllen;		/* ancillary data buffer length */
	unsigned int	msg_flags;		/* flags on received message */
};

//ioctl cmd
// #define FIDEDUPERANGE	3222836278
#define FS_IOC_RESVSP		1076910120
#define FS_IOC_RESVSP64		1076910122
#define FIBMAP	   1
#define FIOASYNC	0x5452
#define FIOQSIZE	0x5460
#define FS_IOC_FIEMAP 3223348747
#define FIGETBSZ 2
#define FICLONERANGE	1075876877
#define TCGETS		0x5401
#define TCSETS		0x5402
#define TCSETSW		0x5403
#define TCSETSF		0x5404
#define TCGETA		0x5405
#define TCSETA		0x5406
#define TCSETAW		0x5407
#define TCSETAF		0x5408
#define TCSBRK		0x5409
#define TCXONC		0x540A
#define TCFLSH		0x540B
#define TIOCEXCL	0x540C
#define TIOCNXCL	0x540D
#define TIOCSCTTY	0x540E
#define TIOCGPGRP	0x540F
#define TIOCSPGRP	0x5410
#define TIOCOUTQ	0x5411
#define TIOCSTI		0x5412
#define TIOCGWINSZ	0x5413
#define TIOCSWINSZ	0x5414
#define TIOCMGET	0x5415
#define TIOCMBIS	0x5416
#define TIOCMBIC	0x5417
#define TIOCMSET	0x5418
#define TIOCGSOFTCAR	0x5419
#define TIOCSSOFTCAR	0x541A
#define FIONREAD	0x541B
#define TIOCINQ		FIONREAD
#define TIOCLINUX	0x541C
#define TIOCCONS	0x541D
#define TIOCGSERIAL	0x541E
#define TIOCSSERIAL	0x541F
#define TIOCPKT		0x5420
#define FIONBIO		0x5421
#define TIOCNOTTY	0x5422
#define TIOCSETD	0x5423
#define TIOCGETD	0x5424
#define TCSBRKP		0x5425
#define TIOCSBRK	0x5427 
#define TIOCCBRK	0x5428 
#define TIOCGSID	0x5429 
#define TCGETS2		2150388778
#define TCSETS2		1076646955
#define TCSETSW2	1076646956
#define TCSETSF2	1076646957
#define TIOCGRS485	0x542E
#define TIOCSRS485	0x542F
#define TIOCGPTN	2147767344
#define TIOCSPTLCK	2147767344 
#define TIOCGDEV	2147767344
#define TCGETX		0x5432 
#define TCSETX		0x5433
#define TCSETXF		0x5434
#define TCSETXW		0x5435
#define TIOCGLCKTRMIOS	0x5456
#define TIOCSLCKTRMIOS	0x5457
#define TIOCGSOFTCAR	0x5419
#define TIOCSSOFTCAR	0x541A

/* optname */
#define SO_LINGER	13
#define SO_ATTACH_FILTER	26

#endif /* GPT_H */
