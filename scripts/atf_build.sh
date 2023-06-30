#!/bin/sh
# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
PROJ_DIR="$(dirname $SCRIPT_DIR)"
THIRD_PARTY_DIR=$PROJ_DIR/third-parties
PROJ_CONF_DIR=$PROJ_DIR/configs
DEV_WORKSPACE_DIR="dev_workspace" 

# third party package directories
TF_A_DIR=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/arm-tf

# toolchain 
CROSS_COMPILE=$THIRD_PARTY_DIR/gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf/bin/aarch64-none-elf-

print_config() {
    echo "=== Configurations ==="
    echo "=> THIRD_PARTY_DIR=$PROJ_DIR/third-parties"
    echo "=> CROSS_COMPILE=$CROSS_COMPILE"
}


compile_TF_A() {
    cd $TF_A_DIR
    make realclean
    make CROSS_COMPILE=$CROSS_COMPILE \
         PLAT=fvp \
         ENABLE_RME=1 \
         FVP_HW_CONFIG_DTS=fdts/fvp-base-gicv3-psci-1t.dts \
         DEBUG=1 \
         LOG_LEVEL=40 \
         ARCH=aarch64 \
         ARM_DISABLE_TRUSTED_WDOG=1 \
         BL33=$PROJ_CONF_DIR/uboot.bin \
         all fip
}

compile_TF_A

