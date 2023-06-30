/*
 * Copyright (c) 2018-2020, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ARM_ARCH_SVC_H
#define ARM_ARCH_SVC_H

#define SMCCC_VERSION			U(0x80000000)
#define SMCCC_ARCH_FEATURES		U(0x80000001)
#define SMCCC_ARCH_SOC_ID		U(0x80000002)
#define SMCCC_ARCH_WORKAROUND_1		U(0x80008000)
#define SMCCC_ARCH_WORKAROUND_2		U(0x80007FFF)

#define SMCCC_GET_SOC_VERSION		U(0)
#define SMCCC_GET_SOC_REVISION		U(1)

//shelter api 0x80000F00 ~ 0x80001000
#define ENC_NEW_TEST    U(0x80000FFE)
#define TASK_EXIT_TEST    U(0x80000FFF)
#define ENC_STATUS    U(0x80001000)
#define ENC_EXCEPTION    U(0x80000F00)
#define ENC_SET_PAGE    U(0x80000F01)
#define ENC_MEM_EXPAND    U(0x80000F02)
#define ENC_CLONE    U(0x80000F03)

#define ENC_NC_NS    U(0x80000FFD)
#define ENC_DESTROY   U(0x80000FF0)
#define ENC_ENTER   U(0x80000FF1)


#endif /* ARM_ARCH_SVC_H */
