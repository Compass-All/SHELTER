#!/bin/bash

SCRIPT_DIR="$(dirname $(readlink -f "$0"))"

source $SCRIPT_DIR/config.sh 

# log files
if [ ! -d $LOG_DIR ]; then
    mkdir -p $LOG_DIR
fi
uart0_log=$LOG_DIR/uart0-fvp.log
uart1_log=$LOG_DIR/uart1-fvp.log
uart2_log=$LOG_DIR/uart2-fvp.log
uart3_log=$LOG_DIR/uart3-fvp.log


FS_IMG_PATH=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/lt-vexpress64-openembedded_lamp-armv8.img
# tf-a 
ATF_OUT_PATH=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/arm-tf/build/fvp/debug

#linux imae
LINUX_IMAGE=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/linux/out/fvp/mobile_oe/arch/arm64/boot/Image

# command
FVP_LAUNCH_OPS="-C pctl.startup=0.0.0.0 -C bp.secure_memory=0 \
 -C cluster0.NUM_CORES=3 -C cluster1.NUM_CORES=0 -C cache_state_modelled=0 -C bp.pl011_uart0.untimed_fifos=1 -C bp.pl011_uart0.unbuffered_output=1 \
-C bp.pl011_uart0.out_file=$uart0_log -C bp.pl011_uart1.out_file=$uart1_log -C bp.pl011_uart2.out_file=$uart2_log -C bp.pl011_uart3.out_file=$uart3_log \
-C bp.ve_sysregs.mmbSiteDefault=0 -C bp.ve_sysregs.exit_on_shutdown=1  -C cluster0.has_rme=1 -C cluster0.max_32bit_el=-1 -C cluster0.gicv3.without-DS-support=1 -C cluster0.gicv4.mask-virtual-interrupt=1 -C cluster0.has_v8_7_pmu_extension=2 -C cluster0.has_rndr=1 -C cluster0.gicv3.cpuintf-mmap-access-level=2    -C cluster1.has_rme=1 -C cluster1.max_32bit_el=-1 -C cluster1.gicv3.without-DS-support=1 -C cluster1.gicv4.mask-virtual-interrupt=1 -C cluster1.has_v8_7_pmu_extension=2 -C cluster1.has_rndr=1 -C cluster1.gicv3.cpuintf-mmap-access-level=2 \
-C bp.secureflashloader.fname=$ATF_OUT_PATH/bl1.bin -C bp.flashloader0.fname=$ATF_OUT_PATH/fip.bin  --data cluster0.cpu0=$PROJ_CONF_DIR/fvp-base-aemv8a-aemv8a.dtb@0x82000000 --data cluster0.cpu0=$PROJ_CONF_DIR/ramdisk.img@0x84000000 \
-C bp.virtioblockdevice.image_path=$FS_IMG_PATH  \
--data cluster0.cpu0=$LINUX_IMAGE@0x80080000 \
-C bp.hostbridge.interfaceName=tap0 -C bp.smsc_91c111.enabled=true -C bp.smsc_91c111.mac_address=00:02:F7:C1:9F:81"

start_fvp_new() {
    # check tap0 network interface
    ifconfig tap0 > /dev/null 2>&1
    if [ $? != 0 ]; then
        log "Creating network interface tap0..."
        sudo ip tuntap add dev tap0 mode tap user $(whoami)
        sudo ifconfig tap0 0.0.0.0 promisc up
        sudo brctl addif virbr0 tap0
    fi
    $FVP $FVP_LAUNCH_OPS
}

# xterm settings
xrdb -merge ~/.Xresources

# log the options
log "Launch options:"
echo $FVP_LAUNCH_OPS
start_fvp_new

