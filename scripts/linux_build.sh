#!/bin/bash

# define variables
#PLATFORM="aemfvp-a"
DEV_WORKSPACE_PLATFORM="fvp"
DEV_WORKSPACE_FS="oe"
DEV_WORKSPACE_LINUX_OE=""

if [[ $DEV_WORKSPACE_FS=="oe" ]]; then
    DEV_WORKSPACE_LINUX_OE="mobile_oe"
fi

# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source $SCRIPT_DIR/config.sh 

# setup (build | clean | package)
#
# FVP workspace is deprecated
# Use DEV_WORKSPACE instead.

#  configuration
config_dev_workspace() {
    # for fvp
    cp $PROJ_CONF_DIR/$DEV_WORKSPACE_DIR/common.fvp $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/build-scripts/configs/common/common.fvp
    
    # for juno
    cp $PROJ_CONF_DIR/$DEV_WORKSPACE_DIR/common.juno $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/build-scripts/configs/common/common.juno
}

# all: (linux, uboot, target-bin)
dev_workspace_build_all() {
    pushd $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR
    config_dev_workspace
    log "Running script:\n\tbuild-scripts/build-all.sh -p $DEV_WORKSPACE_PLATFORM -f $DEV_WORKSPACE_FS $1"
    ./build-scripts/build-all.sh -p $DEV_WORKSPACE_PLATFORM -f $DEV_WORKSPACE_FS $1
    popd
}

dev_workspace_build_linux() {
    pushd $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR
    # replace dts for juno
    K_CFG=""
    if [[ $DEV_WORKSPACE_PLATFORM == "juno" ]]; then
        J_DTS=$PROJ_CONF_DIR/juno-fdts/juno-base.dtsi
        log "Replace dts: $J_DTS => linux/arch/arm64/boot/dts/arm/juno-base.dtsi"
        log "Replace dts: $J_DTS => linux/arch/arm/boot/dts/juno-base.dtsi"
        cp $J_DTS linux/arch/arm64/boot/dts/arm/juno-base.dtsi
        cp $J_DTS linux/arch/arm/boot/dts/juno-base.dtsi
	K_CFG=.kernel_config_juno
    else
	K_CFG=.kernel_config
    fi
    # detect if the linux has already been build
    LINUX_OUT_DIR=linux/out/$DEV_WORKSPACE_PLATFORM/$DEV_WORKSPACE_LINUX_OE
    if [[ -d $LINUX_OUT_DIR && ($1 == "build" || $1 == "all") ]]; then
        pushd $LINUX_OUT_DIR
        log "Linux has been built at linux/out/$DEV_WORKSPACE_PLATFORM/$DEV_WORKSPACE_LINUX_OE."
        log "Re-build now (based on .config: $PROJ_CONF_DIR/$K_CFG)."
        log "make -j8 ARCH=arm64 CROSS_COMPILE=$CROSS_COMPILE_LINARO"

        # prepare .config
        cp $PROJ_CONF_DIR/$K_CFG .config

        make -j8 ARCH=arm64 CROSS_COMPILE=$CROSS_COMPILE_LINARO
        popd
        # log "Package now."
        # ./build-scripts/build-all.sh -p $DEV_WORKSPACE_PLATFORM -f $DEV_WORKSPACE_FS package
    else
        log "Starting build linux for $DEV_WORKSPACE_PLATFORM..."
        ./build-scripts/build-linux.sh -p $DEV_WORKSPACE_PLATFORM -f $DEV_WORKSPACE_FS build
        pushd $LINUX_OUT_DIR
        log "Re-build (based on .config: $PROJ_CONF_DIR/$K_CFG)."
        log "make -j8 ARCH=arm64 CROSS_COMPILE=$CROSS_COMPILE_LINARO"

        # prepare .config
        cp $PROJ_CONF_DIR/$K_CFG .config

        make -j8 ARCH=arm64 CROSS_COMPILE=$CROSS_COMPILE_LINARO
        popd
        # log "Package now."
        # ./build-scripts/build-all.sh -p $DEV_WORKSPACE_PLATFORM -f $DEV_WORKSPACE_FS package
    fi
}

# dev_workspace_build_uboot() {
#     pushd $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR
#     if [[ $DEV_WORKSPACE_PLATFORM == "juno" ]]; then
#         BOARDS="vexpress_aemv8a_juno"
#     else
#         BOARDS="vexpress_aemv8a_semi"
#         UBOOT_CFG=vexpress_aemv8a_semi_defconfig
#         # prepare .config
#         cp $PROJ_CONF_DIR/$UBOOT_CFG u-boot/configs
#     fi
#     config_dev_workspace
#     UBOOT_OUT_DIR=output/$BOARDS

#     if [[ -d u-boot/$UBOOT_OUT_DIR && ($1 == "build" || $1 == "all") ]]; then
#         pushd u-boot
#         log "Uboot has been built at $UBOOT_OUT_DIR."
#         log "Re-build now."
#         log "make -j8 ARCH=aarch64 O=$UBOOT_OUT_DIR"
#         export ARCH=aarch64
#         make -j8 O=$UBOOT_OUT_DIR
#         cp -R $UBOOT_OUT_DIR/tools $UBOOT_OUT_DIR/../
#         popd
#         if [[ $1 == "all" ]]; then
#             log "Package now."
#             ./build-scripts/build-all.sh -p $DEV_WORKSPACE_PLATFORM -f $DEV_WORKSPACE_FS package
#         fi
#     else
#         log "Running script:\n\tbuild-scripts/build-uboot.sh -p $DEV_WORKSPACE_PLATFORM -f $DEV_WORKSPACE_FS $1"
#         ./build-scripts/build-uboot.sh -f $DEV_WORKSPACE_FS -p $DEV_WORKSPACE_PLATFORM $1
#     fi
#     popd
# }

# dev_workspace_build_target-bins() {
#     pushd $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR
#     config_dev_workspace
#     log "Running script:\n\tbuild-scripts/build-target-bins.sh -p $DEV_WORKSPACE_PLATFORM -f $DEV_WORKSPACE_FS $1"
#     ./build-scripts/build-target-bins.sh -p $DEV_WORKSPACE_PLATFORM -f $DEV_WORKSPACE_FS $1
#     popd
# }


__print_usage()
{
	log "Usage: linux_build.sh -s <software> -p [juno|fvp] <command>"
	log "linux_build.sh -s linux -p fvp all"
	log "linux_build.sh: Builds the platform software stack with the"
	log "targeted software component."
	log
    log "Supported software is - linux"
	log "Supported build commands are - clean/build/all"
	log
	exit 0
}

env_build_parse_params() {
	#Parse the named parameters
	while getopts "s:p:" opt; do
		case $opt in
			s)
				FVP_SOFTWARE="$OPTARG"
				;;
            p)
                DEV_WORKSPACE_PLATFORM="$OPTARG"
                ;;
		esac
	done

	#The clean/build/package/all should be after the other options
	#So grab the parameters after the named param option index
	BUILD_CMD=${@:$OPTIND:1}

	#Ensure that the platform is supported
	if [ -z "$FVP_SOFTWARE" ] ; then
        __print_usage
        return
	fi

	#Ensure a build command is specified
	if [ -z "$BUILD_CMD" ] ; then
		__print_usage
        return
	fi
}



# source $SCRIPT_DIR/env_fetch.sh
env_build_parse_params $@
# override command line parameters
if [ "$(type -t dev_workspace_build_${FVP_SOFTWARE})" == function ]; then 
    dev_workspace_build_${FVP_SOFTWARE} $BUILD_CMD
else 
    __print_usage
    exit
fi
