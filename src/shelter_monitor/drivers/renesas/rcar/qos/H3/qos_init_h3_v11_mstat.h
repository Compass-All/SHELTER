/*
 * Copyright (c) 2015-2019, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if RCAR_QOS_TYPE  == RCAR_QOS_TYPE_DEFAULT
static const uint64_t mstat_fix[] = {
	/* 0x0000, */ 0x0000000000000000UL,
	/* 0x0008, */ 0x0000000000000000UL,
	/* 0x0010, */ 0x0000000000000000UL,
	/* 0x0018, */ 0x0000000000000000UL,
	/* 0x0020, */ 0x0000000000000000UL,
	/* 0x0028, */ 0x0000000000000000UL,
	/* 0x0030, */ 0x001004030000FFFFUL,
	/* 0x0038, */ 0x001008060000FFFFUL,
	/* 0x0040, */ 0x001414090000FFFFUL,
	/* 0x0048, */ 0x0000000000000000UL,
	/* 0x0050, */ 0x001410010000FFFFUL,
	/* 0x0058, */ 0x00140C0C0000FFFFUL,
	/* 0x0060, */ 0x00140C0C0000FFFFUL,
	/* 0x0068, */ 0x0000000000000000UL,
	/* 0x0070, */ 0x001410010000FFFFUL,
	/* 0x0078, */ 0x001008060000FFFFUL,
	/* 0x0080, */ 0x001004020000FFFFUL,
	/* 0x0088, */ 0x001414090000FFFFUL,
	/* 0x0090, */ 0x00140C0C0000FFFFUL,
	/* 0x0098, */ 0x001408080000FFFFUL,
	/* 0x00A0, */ 0x000C08020000FFFFUL,
	/* 0x00A8, */ 0x000C04010000FFFFUL,
	/* 0x00B0, */ 0x000C04010000FFFFUL,
	/* 0x00B8, */ 0x0000000000000000UL,
	/* 0x00C0, */ 0x000C08020000FFFFUL,
	/* 0x00C8, */ 0x000C04010000FFFFUL,
	/* 0x00D0, */ 0x000C04010000FFFFUL,
	/* 0x00D8, */ 0x000C04030000FFFFUL,
	/* 0x00E0, */ 0x000C100F0000FFFFUL,
	/* 0x00E8, */ 0x0000000000000000UL,
	/* 0x00F0, */ 0x001010080000FFFFUL,
	/* 0x00F8, */ 0x001010080000FFFFUL,
	/* 0x0100, */ 0x0000000000000000UL,
	/* 0x0108, */ 0x000C04030000FFFFUL,
	/* 0x0110, */ 0x001010080000FFFFUL,
	/* 0x0118, */ 0x001010080000FFFFUL,
	/* 0x0120, */ 0x0000000000000000UL,
	/* 0x0128, */ 0x000C100E0000FFFFUL,
	/* 0x0130, */ 0x0000000000000000UL,
	/* 0x0138, */ 0x001008050000FFFFUL,
	/* 0x0140, */ 0x001008050000FFFFUL,
	/* 0x0148, */ 0x001008050000FFFFUL,
	/* 0x0150, */ 0x001008050000FFFFUL,
	/* 0x0158, */ 0x001008050000FFFFUL,
	/* 0x0160, */ 0x001008050000FFFFUL,
	/* 0x0168, */ 0x001008050000FFFFUL,
	/* 0x0170, */ 0x001008050000FFFFUL,
	/* 0x0178, */ 0x001004030000FFFFUL,
	/* 0x0180, */ 0x001004030000FFFFUL,
	/* 0x0188, */ 0x001004030000FFFFUL,
	/* 0x0190, */ 0x001014140000FFFFUL,
	/* 0x0198, */ 0x001014140000FFFFUL,
	/* 0x01A0, */ 0x001008050000FFFFUL,
	/* 0x01A8, */ 0x001008050000FFFFUL,
	/* 0x01B0, */ 0x001008050000FFFFUL,
	/* 0x01B8, */ 0x0000000000000000UL,
	/* 0x01C0, */ 0x0000000000000000UL,
	/* 0x01C8, */ 0x0000000000000000UL,
	/* 0x01D0, */ 0x0000000000000000UL,
	/* 0x01D8, */ 0x0000000000000000UL,
	/* 0x01E0, */ 0x0000000000000000UL,
	/* 0x01E8, */ 0x0000000000000000UL,
	/* 0x01F0, */ 0x0000000000000000UL,
	/* 0x01F8, */ 0x0000000000000000UL,
	/* 0x0200, */ 0x0000000000000000UL,
	/* 0x0208, */ 0x0000000000000000UL,
	/* 0x0210, */ 0x0000000000000000UL,
	/* 0x0218, */ 0x0000000000000000UL,
	/* 0x0220, */ 0x0000000000000000UL,
	/* 0x0228, */ 0x0000000000000000UL,
	/* 0x0230, */ 0x0000000000000000UL,
	/* 0x0238, */ 0x0000000000000000UL,
	/* 0x0240, */ 0x0000000000000000UL,
	/* 0x0248, */ 0x0000000000000000UL,
	/* 0x0250, */ 0x0000000000000000UL,
	/* 0x0258, */ 0x0000000000000000UL,
	/* 0x0260, */ 0x0000000000000000UL,
	/* 0x0268, */ 0x001408010000FFFFUL,
	/* 0x0270, */ 0x001404010000FFFFUL,
	/* 0x0278, */ 0x0000000000000000UL,
	/* 0x0280, */ 0x0000000000000000UL,
	/* 0x0288, */ 0x0000000000000000UL,
	/* 0x0290, */ 0x001408010000FFFFUL,
	/* 0x0298, */ 0x001404010000FFFFUL,
	/* 0x02A0, */ 0x000C04010000FFFFUL,
	/* 0x02A8, */ 0x000C04010000FFFFUL,
	/* 0x02B0, */ 0x001404010000FFFFUL,
	/* 0x02B8, */ 0x0000000000000000UL,
	/* 0x02C0, */ 0x0000000000000000UL,
	/* 0x02C8, */ 0x0000000000000000UL,
	/* 0x02D0, */ 0x000C04010000FFFFUL,
	/* 0x02D8, */ 0x000C04010000FFFFUL,
	/* 0x02E0, */ 0x001404010000FFFFUL,
	/* 0x02E8, */ 0x0000000000000000UL,
	/* 0x02F0, */ 0x0000000000000000UL,
	/* 0x02F8, */ 0x0000000000000000UL,
	/* 0x0300, */ 0x0000000000000000UL,
	/* 0x0308, */ 0x0000000000000000UL,
	/* 0x0310, */ 0x0000000000000000UL,
	/* 0x0318, */ 0x0000000000000000UL,
	/* 0x0320, */ 0x0000000000000000UL,
	/* 0x0328, */ 0x0000000000000000UL,
	/* 0x0330, */ 0x0000000000000000UL,
	/* 0x0338, */ 0x0000000000000000UL,
};

static const uint64_t mstat_be[] = {
	/* 0x0000, */ 0x001200100C89C401UL,
	/* 0x0008, */ 0x001200100C89C401UL,
	/* 0x0010, */ 0x001200100C89C401UL,
	/* 0x0018, */ 0x001200100C89C401UL,
	/* 0x0020, */ 0x001100100C803401UL,
	/* 0x0028, */ 0x001100100C80FC01UL,
	/* 0x0030, */ 0x0000000000000000UL,
	/* 0x0038, */ 0x0000000000000000UL,
	/* 0x0040, */ 0x0000000000000000UL,
	/* 0x0048, */ 0x0000000000000000UL,
	/* 0x0050, */ 0x0000000000000000UL,
	/* 0x0058, */ 0x0000000000000000UL,
	/* 0x0060, */ 0x0000000000000000UL,
	/* 0x0068, */ 0x001100100C803401UL,
	/* 0x0070, */ 0x0000000000000000UL,
	/* 0x0078, */ 0x0000000000000000UL,
	/* 0x0080, */ 0x0000000000000000UL,
	/* 0x0088, */ 0x0000000000000000UL,
	/* 0x0090, */ 0x0000000000000000UL,
	/* 0x0098, */ 0x0000000000000000UL,
	/* 0x00A0, */ 0x0000000000000000UL,
	/* 0x00A8, */ 0x0000000000000000UL,
	/* 0x00B0, */ 0x0000000000000000UL,
	/* 0x00B8, */ 0x001100100C803401UL,
	/* 0x00C0, */ 0x0000000000000000UL,
	/* 0x00C8, */ 0x0000000000000000UL,
	/* 0x00D0, */ 0x0000000000000000UL,
	/* 0x00D8, */ 0x0000000000000000UL,
	/* 0x00E0, */ 0x0000000000000000UL,
	/* 0x00E8, */ 0x001100100C803401UL,
	/* 0x00F0, */ 0x0000000000000000UL,
	/* 0x00F8, */ 0x0000000000000000UL,
	/* 0x0100, */ 0x0000000000000000UL,
	/* 0x0108, */ 0x0000000000000000UL,
	/* 0x0110, */ 0x0000000000000000UL,
	/* 0x0118, */ 0x0000000000000000UL,
	/* 0x0120, */ 0x0000000000000000UL,
	/* 0x0128, */ 0x0000000000000000UL,
	/* 0x0130, */ 0x001100100C803401UL,
	/* 0x0138, */ 0x0000000000000000UL,
	/* 0x0140, */ 0x0000000000000000UL,
	/* 0x0148, */ 0x0000000000000000UL,
	/* 0x0150, */ 0x0000000000000000UL,
	/* 0x0158, */ 0x0000000000000000UL,
	/* 0x0160, */ 0x0000000000000000UL,
	/* 0x0168, */ 0x0000000000000000UL,
	/* 0x0170, */ 0x0000000000000000UL,
	/* 0x0178, */ 0x0000000000000000UL,
	/* 0x0180, */ 0x0000000000000000UL,
	/* 0x0188, */ 0x0000000000000000UL,
	/* 0x0190, */ 0x0000000000000000UL,
	/* 0x0198, */ 0x0000000000000000UL,
	/* 0x01A0, */ 0x0000000000000000UL,
	/* 0x01A8, */ 0x0000000000000000UL,
	/* 0x01B0, */ 0x0000000000000000UL,
	/* 0x01B8, */ 0x001100100C803401UL,
	/* 0x01C0, */ 0x001100800C8FFC01UL,
	/* 0x01C8, */ 0x001100800C8FFC01UL,
	/* 0x01D0, */ 0x001100800C8FFC01UL,
	/* 0x01D8, */ 0x001100800C8FFC01UL,
	/* 0x01E0, */ 0x001100100C80FC01UL,
	/* 0x01E8, */ 0x001200100C80FC01UL,
	/* 0x01F0, */ 0x001100100C80FC01UL,
	/* 0x01F8, */ 0x001100100C803401UL,
	/* 0x0200, */ 0x001100100C80FC01UL,
	/* 0x0208, */ 0x001200100C80FC01UL,
	/* 0x0210, */ 0x001100100C80FC01UL,
	/* 0x0218, */ 0x001100100C825801UL,
	/* 0x0220, */ 0x001100100C825801UL,
	/* 0x0228, */ 0x001100100C803401UL,
	/* 0x0230, */ 0x001100100C825801UL,
	/* 0x0238, */ 0x001100100C825801UL,
	/* 0x0240, */ 0x001200100C8BB801UL,
	/* 0x0248, */ 0x001100200C8FFC01UL,
	/* 0x0250, */ 0x001200100C8BB801UL,
	/* 0x0258, */ 0x001100200C8FFC01UL,
	/* 0x0260, */ 0x001100100C84E401UL,
	/* 0x0268, */ 0x0000000000000000UL,
	/* 0x0270, */ 0x0000000000000000UL,
	/* 0x0278, */ 0x001100100C81F401UL,
	/* 0x0280, */ 0x001100100C803401UL,
	/* 0x0288, */ 0x001100100C803401UL,
	/* 0x0290, */ 0x0000000000000000UL,
	/* 0x0298, */ 0x0000000000000000UL,
	/* 0x02A0, */ 0x0000000000000000UL,
	/* 0x02A8, */ 0x0000000000000000UL,
	/* 0x02B0, */ 0x0000000000000000UL,
	/* 0x02B8, */ 0x001100100C803401UL,
	/* 0x02C0, */ 0x001100100C803401UL,
	/* 0x02C8, */ 0x001100100C803401UL,
	/* 0x02D0, */ 0x0000000000000000UL,
	/* 0x02D8, */ 0x0000000000000000UL,
	/* 0x02E0, */ 0x0000000000000000UL,
	/* 0x02E8, */ 0x001100100C803401UL,
	/* 0x02F0, */ 0x001100300C8FFC01UL,
	/* 0x02F8, */ 0x001100500C8FFC01UL,
	/* 0x0300, */ 0x001100100C803401UL,
	/* 0x0308, */ 0x001100300C8FFC01UL,
	/* 0x0310, */ 0x001100500C8FFC01UL,
	/* 0x0318, */ 0x001200100C803401UL,
	/* 0x0320, */ 0x001100300C8FFC01UL,
	/* 0x0328, */ 0x001100500C8FFC01UL,
	/* 0x0330, */ 0x001100300C8FFC01UL,
	/* 0x0338, */ 0x001100500C8FFC01UL,
};
#endif
