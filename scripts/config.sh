#!/bin/bash
# packages & sources
export CROSS_COMPILE_SRC="https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf.tar.xz"
export CROSS_COMPILE_SRC_AARCH64="https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-aarch64-aarch64-none-elf.tar.xz"
export FVP_SRC="https://armkeil.blob.core.windows.net/developer/Files/downloads/ecosystem-models/FVP_Base_RevC-2xAEMvA_11.20_15_Linux64.tgz"
export FVP_SRC_AARCH64="https://developer.arm.com/-/media/Files/downloads/ecosystem-models/FVP_Base_RevC-2xAEMvA_11.20_15_Linux64_armv8l.tgz"
export TF_A_SRC="https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git/snapshot/trusted-firmware-a-arm_cca_v0.3.tar.gz"
export ARM_REF_PLAT_SRC="https://git.linaro.org/landing-teams/working/arm/arm-reference-platforms.git"
export DEV_WORKSPACE_SRC="https://git.linaro.org/landing-teams/working/arm/manifest"
export ARN_UBUNTU_IMG_SRC="https://old-releases.ubuntu.com/releases/focal/ubuntu-20.04-live-server-arm64.iso"
## for linaro workspace 
export LINARO_CROSS_COMPILE_SRC="https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/aarch64-linux-gnu/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu.tar.xz"
export LINARO_CROSS_COMPILE_GNUEABIHF_SRC="https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/arm-linux-gnueabihf/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf.tar.xz"
export OELAMP_IMG_SRC="https://releases.linaro.org/openembedded/juno-lsk/15.09/lt-vexpress64-openembedded_lamp-armv8-gcc-4.9_20150912-729.img.gz"
# SH
export SH="/bin/bash"

# project structure directories
export SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
export PROJ_DIR="$(dirname $SCRIPT_DIR)"
export SRC_DIR=$PROJ_DIR/src
export SHELTER_MONITOR_DIR="shelter_monitor"
export SHELTER_KERNEL_DIR="linux"
export EL2TEST_DIR=$SRC_DIR/empirical_el2
export EMU_DIR=$PROJ_DIR/emulate
export PROJ_CONF_DIR=$PROJ_DIR/configs
export THIRD_PARTY_DIR=$PROJ_DIR/third-parties
export DBG_DIR=$PROJ_DIR/debug 
export LOG_DIR=$PROJ_DIR/debug/logs

# package dsts
export CROSS_COMPILE_DIR="gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf"
export CROSS_COMPILE_DIR_AARCH64="gcc-arm-10.3-2021.07-aarch64-aarch64-none-elf"
export FVP_DIR="Base_RevC_AEMvA_pkg"
export TF_A_DIR="trusted-firmware-a-arm_cca_v0.3"
export TF_EVA_DIR="arm-tf"
export ARM_REF_PLAT_DIR="arm-reference-platforms"
export LINUX_DISTRO_IMG="ubuntu-20.04-live-server-arm64.iso"
export OELAMP_IMG="lt-vexpress64-openembedded_lamp-armv8.img"
export SATA_DIR="satadisks"

# el2 test
export EL2TEST_ATF="arm-tf"
export EL2TEST_LINUX="linux-4.14"

# juno emulate test
export EMU_ATF="arm-tf-dev"
export EMU_LINUX="linux-juno-dev"

# workspace
export DEV_WORKSPACE_DIR="dev_workspace"    # linaro development platform workspace
export FVP_WORKSPACE_DIR="aemfvp-a_workspace" # deprecated
export FVP_WORKSPACE_TF_A_DIR="arm-tf"        # deprecated
# bin locations
if [[ "$(uname -m)" != "aarch64" ]]; then
    export CROSS_COMPILE=$THIRD_PARTY_DIR/$CROSS_COMPILE_DIR/bin/aarch64-none-elf-
    export CROSS_COMPILE_LINARO=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
else
    # export CROSS_COMPILE=$THIRD_PARTY_DIR/$CROSS_COMPILE_DIR_AARCH64/bin/aarch64-none-elf-
    export CROSS_COMPILE=/usr/bin/
    export CROSS_COMPILE_LINARO=$CROSS_COMPILE
fi

if [[ "$(uname -m)" == "aarch64" ]]; then
    export FVP=$THIRD_PARTY_DIR/$FVP_DIR/models/Linux64_armv8l_GCC-9.3/FVP_Base_RevC-2xAEMvA
else
    export FVP=$THIRD_PARTY_DIR/$FVP_DIR/models/Linux64_GCC-9.3/FVP_Base_RevC-2xAEMvA
fi

export MODEL=${FVP}
# color
export GREEN='\033[0;32m'
export NC='\033[0m' # No Color
export RED='\033[0;31m'
# repo command
export PATH=${THIRD_PARTY_DIR}/.bin:${PATH}

#
# Functions
#

print_config() {
    echo "=== Configurations ==="
    echo "=> THIRD_PARTY_DIR=$PROJ_DIR/third-parties"
    echo "=> CROSS_COMPILE=$CROSS_COMPILE"
}

log() {
    printf "${GREEN}$1${NC}\n"
}

log_error() {
    printf "${RED}$1${NC}\n"
}