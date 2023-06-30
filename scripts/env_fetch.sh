#!/bin/bash

# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source $SCRIPT_DIR/config.sh 

#
# Functions
#

# print_config() {
#     echo "=== Configurations ==="
#     echo "=> THIRD_PARTY_DIR=$PROJ_DIR/third-parties"
#     echo "=> CROSS_COMPILE=$CROSS_COMPILE"
# }

# log() {
#     printf "${GREEN}$1${NC}\n"
# }

# log_error() {
#     printf "${RED}$1${NC}\n"
# }

prerequisite_fetch() {
    log "===> Downloading prerequisite packages..."
    sudo apt-get update
    sudo apt-get install make autoconf autopoint bc bison build-essential curl \
                         device-tree-compiler dosfstools flex gettext-base git libssl-dev m4 expect\
                         mtools parted pkg-config python python3-distutils rsync unzip uuid-dev \
                         wget acpica-tools fuseext2 iasl telnet xterm -y
    # needed for fvp network configuration
    sudo apt install libvirt-daemon-system libvirt-clients bridge-utils -y
    # others
    sudo apt install libelf-dev gawk -y
    if [[ "$(uname -m)" == "aarch64" ]]; then
        sudo apt install flex bison device-tree-compiler libssl-dev xterm -y
    else
        # fetch `repo` command
        if [ ! -d $THIRD_PARTY_DIR/.bin ]; then
            mkdir -p $THIRD_PARTY_DIR/.bin
        fi
        if [[ ! "$PATH" =~ (^|:)"${THIRD_PARTY_DIR}/.bin"(:|$) ]]; then
            echo -e "\n# repo command" >> $SCRIPT_DIR/config.sh
            echo -e "export PATH="\${THIRD_PARTY_DIR}/.bin:\${PATH}"" >> $SCRIPT_DIR/config.sh
        fi
        curl https://storage.googleapis.com/git-repo-downloads/repo > ${THIRD_PARTY_DIR}/.bin/repo
        chmod a+rx ${THIRD_PARTY_DIR}/.bin/repo
        # python2 pip  
    fi
}

# cross compiling
cross_compile_fetch() {
    cd $THIRD_PARTY_DIR

    if [[ "$(uname -m)" != "aarch64" ]]; then
        CC_DIR="gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf"
    else
        CC_DIR="gcc-arm-10.3-2021.07-aarch64-aarch64-none-elf"
        CROSS_COMPILE_SRC=$CROSS_COMPILE_SRC_AARCH64
    fi

    if [ ! -d $CC_DIR ]; then
        log "===> Downloading the cross compiler..."
        curl $CROSS_COMPILE_SRC | tar xfJ -
        if [ $? -ne 0 ]; then
            log_error "[cross-compiler] Error downloading the cross compiler."
            exit
        fi
    fi
}

# Trusted Firmware
tf_fetch() {
    log "===> Soft linking TF-A (Trusted Firmware)... from src/"
    rm -rf $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/arm-tf
    ln -s $SRC_DIR/$SHELTER_MONITOR_DIR  $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/arm-tf
}

# FVP model
fvp_model_fetch() {
    # chdir
    cd $THIRD_PARTY_DIR

    if [ ! -d Base_RevC_AEMvA_pkg ]; then
        if [[ "$(uname -m)" == "aarch64" ]]; then
            FVP_SRC=$FVP_SRC_AARCH64
            log "===> Downloading Armv-A Based AEM FVP (aarch64-host)..."
            wget -O- $FVP_SRC | tar xvzf -
        else
            log "===> Downloading Armv-A Based AEM FVP (x86-host)..."
            curl $FVP_SRC | tar xzvf -
        fi
        
        if [ $? -ne 0 ]; then
            log_error "[AEM FVP] Error downloading FVP."
            exit
        fi
        # tar xzvf FVP_Base_RevC-2xAEMvA_11.20_15_Linux64.tgz
        # rm FVP_Base_RevC-2xAEMvA_11.20_15_Linux64.tgz
    fi
}

# development workspace
dev_workspace_fetch() {
    pushd $THIRD_PARTY_DIR

    VERSION="19.10"
    MANIFEST="latest"
    if [ ! -d $DEV_WORKSPACE_DIR ]; then 
        log "===> Downloading linaro ARM development platform software ..."
        log "Remeber first to config git: git config --global user.name ..."
        log "NOTE: It may take a long time for fetching. Please wait for a few minutes (~20mins first time)."
        mkdir -p $DEV_WORKSPACE_DIR
        
        pushd $DEV_WORKSPACE_DIR
	# packages
	sudo apt install python3-pyelftools python-dev -y

        # repo init (software stack)
	repo init \
            -u $DEV_WORKSPACE_SRC \
            -b $VERSION \
            -m pinned-${MANIFEST}.xml
        # sync
        repo sync -j8
        popd
    fi

    # other components (oe-filesystem, linaro cross compile)
    if [ ! -d $DEV_WORKSPACE_DIR/tools/gcc ]; then
        log "===> Creating linaro cross compiler ..."
        pushd $DEV_WORKSPACE_DIR
        mkdir -p tools/gcc
        cd tools/gcc

        if [[ "$(uname -m)" != "aarch64" ]]; then
            wget -O- $LINARO_CROSS_COMPILE_SRC | tar xfJ -
            if [ $? -ne 0 ]; then
                rm -rf tools/gcc
                log_error "[linaro_cross-compiler] Error downloading the cross compiler."
                exit
            fi
            wget -O- $LINARO_CROSS_COMPILE_GNUEABIHF_SRC | tar xfJ -
            if [ $? -ne 0 ]; then
                rm -rf tools/gcc
                log_error "[linaro_cross-compiler-gnueabihf] Error downloading the cross compiler-gnueabihf."
                exit
            fi
        else
            # create symbol link
            ln -s $THIRD_PARTY_DIR/$CROSS_COMPILE_DIR_AARCH64 $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/tools/gcc/$CROSS_COMPILE_DIR_AARCH64
            if [ $? -ne 0 ]; then
                rm -rf tools/gcc
                log_error "[linaro_cross-compiler-gnueabihf] Error creating the cross compiler-none."
                exit
            fi
        fi
        popd
    fi

    if [ ! -f $DEV_WORKSPACE_DIR/$OELAMP_IMG ]; then
        log "===> Downloading the oelamp filesystem image ... "
        pushd $DEV_WORKSPACE_DIR
        wget -O- $OELAMP_IMG_SRC | gunzip -c > $OELAMP_IMG
        popd
    fi
    popd
}

link_shelter_kernel_fetch() {
    rm -rf $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/linux
    ln -s $SRC_DIR/$SHELTER_KERNEL_DIR $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/linux
}

third_parties_fetchall() {
    cd $THIRD_PARTY_DIR
    # 1. download cross-compiling 
    cross_compile_fetch
    # 2. download FVP model
    fvp_model_fetch
    # 3. prerequisite packages
    prerequisite_fetch
    # 4. download the arm development workspace
    dev_workspace_fetch
    # 5. link shelter's linux kernel
    link_shelter_kernel_fetch
    # 6. link shelter monitor
    tf_fetch
}

# 1. install third-party packages
if [ ! -d $THIRD_PARTY_DIR ]; then
    log "==> Creating directory $THIRD_PARTY_DIR"
    mkdir -p $THIRD_PARTY_DIR
fi

if [ $# != 1 ]; then
    log_error "Usage: ./env_fetch.sh [all | cross_compile | prerequisite | fvp_model | tf | link_shelter_kernel]"
    exit
fi

if [ $1 == "all" ]; then
    third_parties_fetchall
else 
    if [ "$(type -t $1_fetch)" == function ]; then 
        $1_fetch
    else 
        log_error "Usage: ./env_fetch.sh [all | cross_compile | prerequisite | fvp_model | tf | link_shelter_kernel]"
    fi
fi
