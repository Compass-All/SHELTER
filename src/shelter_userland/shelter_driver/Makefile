PWD         := $(shell pwd) 
KVERSION    := $(shell uname -r)
CURRENT_DIR := $(CURDIR)
PROJ_DIR := $(abspath $(CURRENT_DIR)/../../..)
KDIR   = $(PROJ_DIR)/third-parties/dev_workspace/linux/out/fvp/mobile_oe


MODULE_NAME  = shelter_manager
obj-m       := $(MODULE_NAME).o
$(MODULE_NAME)-objs := shelter_driver.o shelter_vector_table.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm64 CROSS_COMPILE=$(PROJ_DIR)/third-parties/dev_workspace/tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu- modules
	rm -rf *.mod* .*.cmd *.symvers *.order
clean:
	make -C $(KDIR) M=$(PWD) clean