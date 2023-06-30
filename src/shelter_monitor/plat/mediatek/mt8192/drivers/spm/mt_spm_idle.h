/*
 * Copyright (c) 2020, MediaTek Inc. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MT_SPM_IDLE_H
#define MT_SPM_IDLE_H

typedef void (*spm_idle_conduct)(struct spm_lp_scen *spm_lp,
				 unsigned int *resource_req);
int mt_spm_idle_generic_enter(int state_id, unsigned int ext_opand,
			      spm_idle_conduct fn);
void mt_spm_idle_generic_resume(int state_id, unsigned int ext_opand,
				struct wake_status **status);
void mt_spm_idle_generic_init(void);
#endif /* MT_SPM_IDLE_H */
