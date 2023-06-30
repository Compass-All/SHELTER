/*
 * Copyright (c) 2018-2021, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/debug.h>
#include <common/runtime_svc.h>
#include <lib/cpus/errata_report.h>
#include <lib/cpus/wa_cve_2017_5715.h>
#include <lib/cpus/wa_cve_2018_3639.h>
#include <lib/smccc.h>
#include <services/arm_arch_svc.h>
#include <services/rmi_svc.h>
#include <services/rmmd_svc.h>
#include <smccc_helpers.h>
#include <plat/common/platform.h>
#include <lib/gpt/gpt.h>
#include <lib/el3_runtime/context_mgmt.h>

#if ENABLE_RME
/* Setup Arm architecture Services */
static int32_t arm_arch_svc_setup(void)
{
	return rmmd_setup();
}
#endif

unsigned int plat_is_my_cpu_primary(void);

static int32_t smccc_version(void)
{	
	return MAKE_SMCCC_VERSION(SMCCC_MAJOR_VERSION, SMCCC_MINOR_VERSION);
}

static int32_t smccc_arch_features(u_register_t arg1)
{	
	switch (arg1) {
	case SMCCC_VERSION:
	case SMCCC_ARCH_FEATURES:
		return SMC_ARCH_CALL_SUCCESS;
	case SMCCC_ARCH_SOC_ID:
		return plat_is_smccc_feature_available(arg1);
#if WORKAROUND_CVE_2017_5715
	case SMCCC_ARCH_WORKAROUND_1:
		if (check_wa_cve_2017_5715() == ERRATA_NOT_APPLIES)
			return 1;
		return 0; /* ERRATA_APPLIES || ERRATA_MISSING */
#endif

#if WORKAROUND_CVE_2018_3639
	case SMCCC_ARCH_WORKAROUND_2: {
#if DYNAMIC_WORKAROUND_CVE_2018_3639
		unsigned long long ssbs;

		/*
		 * Firmware doesn't have to carry out dynamic workaround if the
		 * PE implements architectural Speculation Store Bypass Safe
		 * (SSBS) feature.
		 */
		ssbs = (read_id_aa64pfr1_el1() >> ID_AA64PFR1_EL1_SSBS_SHIFT) &
			ID_AA64PFR1_EL1_SSBS_MASK;

		/*
		 * If architectural SSBS is available on this PE, no firmware
		 * mitigation via SMCCC_ARCH_WORKAROUND_2 is required.
		 */
		if (ssbs != SSBS_UNAVAILABLE)
			return 1;

		/*
		 * On a platform where at least one CPU requires
		 * dynamic mitigation but others are either unaffected
		 * or permanently mitigated, report the latter as not
		 * needing dynamic mitigation.
		 */
		if (wa_cve_2018_3639_get_disable_ptr() == NULL)
			return 1;
		/*
		 * If we get here, this CPU requires dynamic mitigation
		 * so report it as such.
		 */
		return 0;
#else
		/* Either the CPUs are unaffected or permanently mitigated */
		return SMC_ARCH_CALL_NOT_REQUIRED;
#endif
	}
#endif

	/* Fallthrough */

	default:
		return SMC_UNK;
	}
}

/* return soc revision or soc version on success otherwise
 * return invalid parameter */
static int32_t smccc_arch_id(u_register_t arg1)
{
	if (arg1 == SMCCC_GET_SOC_REVISION) {
		return plat_get_soc_revision();
	}
	if (arg1 == SMCCC_GET_SOC_VERSION) {
		return plat_get_soc_version();
	}
	return SMC_ARCH_CALL_INVAL_PARAM;
}


static int32_t enc_destroy(u_register_t arg1, u_register_t arg2, u_register_t arg3)
{
	if (plat_is_my_cpu_primary() == 1U)
	{
		// return 0;
	}
	return shelter_destruct(arg1, arg2, arg3);
}

static u_register_t enc_enter(u_register_t arg1, u_register_t arg2, u_register_t arg3)
{
	if (plat_is_my_cpu_primary() == 1U)
	{
		// return 0;
	}
	return shelter_enter(arg1, arg2, arg3);
}


static int enc_creation(u_register_t arg1, u_register_t arg2, u_register_t arg3, u_register_t arg4, u_register_t arg5, u_register_t arg6, u_register_t arg7)
{
	if (plat_is_my_cpu_primary() == 1U)
	{
		// return 0;
	}
	return shelter_creation(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

static uint64_t enc_exception_request_os(u_register_t arg1, u_register_t arg2, u_register_t arg3, u_register_t arg4)
{

	return exception_request_os(arg1, arg2, arg3, arg4);
}

static int enc_set_pt(u_register_t arg1, u_register_t arg2, u_register_t arg3, u_register_t arg4)
{

	return shelter_set_page(arg1, arg2, arg3, arg4);
}

static int svc_enc_nc_ns(u_register_t arg1, u_register_t arg2, u_register_t arg3, u_register_t arg4)
{

	return enc_nc_ns(arg1, arg2, arg3, arg4);
}

static int enc_memexpand(u_register_t arg1, u_register_t arg2, u_register_t arg3, u_register_t arg4)
{

	return shelter_memexpand(arg1, arg2, arg3, arg4);
}

static uint32_t enc_clone(u_register_t arg1, u_register_t arg2, u_register_t arg3, u_register_t arg4, u_register_t arg5, u_register_t arg6, u_register_t arg7)
{
	if (plat_is_my_cpu_primary() == 1U)
	{
		// return 0;
	}
	return shelter_clone(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

static int32_t enc_task_exit_test(u_register_t arg1, u_register_t arg2, u_register_t arg3)
{
	if (plat_is_my_cpu_primary() == 1U)
	{
		// return 0;
	}
	return shelter_task_exit(arg1, arg2, arg3);
}

static int32_t enc_status(void)
{	
	unsigned long long scr;
	asm volatile(
		"mrs %0,HCR_EL2\n"
		:"=r"(scr)
		::
		);
	NOTICE("HCR_EL2:%llx\n",scr);

	asm volatile(
		"mrs %0,SCR_EL3\n"
		:"=r"(scr)
		::
		);
	NOTICE("SCR_EL3:%llx\n",scr);

	if (plat_is_my_cpu_primary() == 1U)
	{
		u_register_t gptbr_el3 = read_gptbr_el3();
		NOTICE("primary CPU gptbr_el3:%lx\n",gptbr_el3);
	}

	if (plat_is_my_cpu_primary() == 0U)
	{
		u_register_t gptbr_el3 = read_gptbr_el3();
		NOTICE("secondary CPU gptbr_el3:%lx\n",gptbr_el3);
	}
	return MAKE_SMCCC_VERSION(SMCCC_MAJOR_VERSION, SMCCC_MINOR_VERSION);
}

// static long long getCycle(void){
//         long long r = 0;
// 	asm volatile("mrs %0, pmccntr_el0" : "=r" (r)); 

//         return r;
// }
// uint64_t start3, end3;
/*
 * Top-level Arm Architectural Service SMC handler.
 */
static uintptr_t arm_arch_svc_smc_handler(uint32_t smc_fid,
	u_register_t x1,
	u_register_t x2,
	u_register_t x3,
	u_register_t x4,
	void *cookie,
	void *handle,
	u_register_t flags)
{	
	// NOTICE("arg1:%lx\n", x1);
	// NOTICE("arg2:%lx\n", x2);
	// NOTICE("arg3:%lx\n", x3);
	// NOTICE("arg4:%lx\n", x4);

	if(x1 == 0x1236){

    NOTICE("switch done2. cycle: %ld cycle\n",x3);
	// start3 = getCycle();
		// SMC_RET1(handle, start3);
	}
	// NOTICE("Invoked arm_arch_svc_smc_fid:%x\n", smc_fid);
	u_register_t x5, x6, x7;

	// NOTICE("CPU %u\n",plat_my_core_pos());

	switch (smc_fid) {
	case SMCCC_VERSION:
		SMC_RET1(handle, smccc_version());
	case SMCCC_ARCH_FEATURES:
		SMC_RET1(handle, smccc_arch_features(x1));
	case SMCCC_ARCH_SOC_ID:
		SMC_RET1(handle, smccc_arch_id(x1));
	case ENC_NEW_TEST:
		x5 = SMC_GET_GP(handle, CTX_GPREG_X5);
		x6 = SMC_GET_GP(handle, CTX_GPREG_X6);
		x7 = SMC_GET_GP(handle, CTX_GPREG_X7);
		SMC_RET1(handle, enc_creation(x1, x2, x3, x4, x5, x6, x7));
	case ENC_EXCEPTION:
		SMC_RET1(handle, enc_exception_request_os(x1, x2, x3, x4));
	case ENC_SET_PAGE:
		SMC_RET1(handle, enc_set_pt(x1, x2, x3, x4));
	case TASK_EXIT_TEST:
		SMC_RET1(handle, enc_task_exit_test(x1, x2, x3));
	case ENC_STATUS:
		SMC_RET1(handle, enc_status());
	case ENC_NC_NS:
		SMC_RET1(handle, svc_enc_nc_ns(x1, x2, x3, x4));
	case ENC_MEM_EXPAND:
		SMC_RET1(handle, enc_memexpand(x1, x2, x3, x4));
	case ENC_CLONE:
		x5 = SMC_GET_GP(handle, CTX_GPREG_X5);
		x6 = SMC_GET_GP(handle, CTX_GPREG_X6);
		x7 = SMC_GET_GP(handle, CTX_GPREG_X7);
		SMC_RET1(handle, enc_clone(x1, x2, x3, x4, x5, x6, x7));
	case ENC_DESTROY:
		SMC_RET1(handle, enc_destroy(x1, x2, x3));
	case ENC_ENTER:
		SMC_RET1(handle, enc_enter(x1, x2, x3));
#if WORKAROUND_CVE_2017_5715
	case SMCCC_ARCH_WORKAROUND_1:
		/*
		 * The workaround has already been applied on affected PEs
		 * during entry to EL3.  On unaffected PEs, this function
		 * has no effect.
		 */
		SMC_RET0(handle);
#endif
#if WORKAROUND_CVE_2018_3639
	case SMCCC_ARCH_WORKAROUND_2:
		/*
		 * The workaround has already been applied on affected PEs
		 * requiring dynamic mitigation during entry to EL3.
		 * On unaffected or statically mitigated PEs, this function
		 * has no effect.
		 */
		SMC_RET0(handle);
#endif
	default:
#if ENABLE_RME
		/*
		 * RMI functions are allocated from the Arch service range. Call
		 * the RMM dispatcher to handle RMI calls.
		 */
		if (is_rmi_fid(smc_fid)) {
			return rmmd_rmi_handler(smc_fid, x1, x2, x3, x4, cookie,
						handle, flags);
		}
#endif
		WARN("Unimplemented Arm Architecture Service Call: 0x%x \n",
			smc_fid);
		SMC_RET1(handle, SMC_UNK);
	}
}

/* Register Standard Service Calls as runtime service */
DECLARE_RT_SVC(
		arm_arch_svc,
		OEN_ARM_START,
		OEN_ARM_END,
		SMC_TYPE_FAST,
#if ENABLE_RME
		arm_arch_svc_setup,
#else
		NULL,
#endif
		arm_arch_svc_smc_handler
);
