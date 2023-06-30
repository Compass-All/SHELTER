/*
 * Copyright (c) 2020, MediaTek Inc. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MT_SPM_SSPM_NOTIFIER_H
#define MT_SPM_SSPM_NOTIFIER_H

enum MT_SPM_SSPM_NOTIFY_ID {
	MT_SPM_NOTIFY_LP_ENTER,
	MT_SPM_NOTIFY_LP_LEAVE,
};

int mt_spm_sspm_notify(int type, unsigned int lp_mode);

static inline int mt_spm_sspm_notify_u32(int type, unsigned int lp_mode)
{
	return mt_spm_sspm_notify(type, lp_mode);
}
#endif /* MT_SPM_SSPM_NOTIFIER_H */
