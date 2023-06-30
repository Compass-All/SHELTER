#
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# TRP source files common to ARM standard platforms
BL32_SOURCES		+=	plat/arm/common/trp/arm_trp_setup.c	\
				plat/arm/common/arm_topology.c		\
				plat/common/aarch64/platform_mp_stack.S
