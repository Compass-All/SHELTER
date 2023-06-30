/*
 * Copyright (c) 2018-2019, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLAT_PRIVATE_H
#define PLAT_PRIVATE_H

#include <lib/xlat_tables/xlat_tables.h>
#include <bl31/interrupt_mgmt.h>

void versal_config_setup(void);

const mmap_region_t *plat_versal_get_mmap(void);

void plat_versal_gic_driver_init(void);
void plat_versal_gic_init(void);
void plat_versal_gic_cpuif_enable(void);
void plat_versal_gic_cpuif_disable(void);
void plat_versal_gic_pcpu_init(void);
void plat_versal_gic_save(void);
void plat_versal_gic_resume(void);

unsigned int versal_calc_core_pos(u_register_t mpidr);
/*
 * Register handler to specific GIC entrance
 * for INTR_TYPE_EL3 type of interrupt
 */
int request_intr_type_el3(uint32_t irq, interrupt_type_handler_t fiq_handler);

#endif /* PLAT_PRIVATE_H */
