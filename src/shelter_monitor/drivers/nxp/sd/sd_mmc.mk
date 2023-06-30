#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

ifeq (${ADD_SD_MMC},)

ADD_SD_MMC	:= 1

SD_DRIVERS_PATH		:=  ${PLAT_DRIVERS_PATH}/sd

SD_MMC_BOOT_SOURCES	+= ${SD_DRIVERS_PATH}/sd_mmc.c \
			   drivers/io/io_block.c

PLAT_INCLUDES		+= -I$(SD_DRIVERS_PATH)

ifeq (${BL_COMM_SD_MMC_NEEDED},yes)
BL_COMMON_SOURCES	+= ${SD_MMC_BOOT_SOURCES}
else
ifeq (${BL2_SD_MMC_NEEDED},yes)
BL2_SOURCES		+= ${SD_MMC_BOOT_SOURCES}
endif
ifeq (${BL3_SD_MMC_NEEDED},yes)
BL31_SOURCES		+= ${SD_MMC_BOOT_SOURCES}
endif
endif
endif
