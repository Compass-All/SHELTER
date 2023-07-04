# Shelter

## Overview

The current version of CCA primarily achieves isolation through the construction of Realm VM using virtualization techniques and does not provide user-level isolation environments.

We propose Shelter as a complement to CCA’s primary Realm VM-style architecture, aiming to allow to deploy applications with isolation in userspace as SApp. Shelter is designed by cooperating with Arm CCA hardware primitive to provide hardware-based isolation while removing the need for software workloads to trust their data to a Host OS, hypervisor, or privileged software (e.g., trusted OS, Secure/Realm hypervisor).
## Prototype

This is a Shelter prototype based on FVP Base RevC-2xAEMvA with RME-enabled features. This document is a user guide on how to set up, build and run Shelter.
	
The code is based on trusted-firmware-a-arm_cca_v0.3 and tested on Ubuntu 20.04.

*Project Directory*:
- `/Path/to/this/repo/SHELTER`/
  - `src` (source code of shelter)
  - `scripts/` (fetch/build/run)
  - `third-parties/` (This directory will be created by `env_fetch.sh` script)
    - `Base_RevC_AEMvA_pkg/` (Contains ARM FVP Base_RevC Model)
    - `dev_workspace/` (Contains Linaro's workspace of software stacks)

## 1. Environment setup

Run `scripts/env_fetch.sh all` to sync the software stacks. This script is used for fetching all the required environments and build up the dirctories to form the *Project Directory*. Remeber first to config git: `git config --global user.name "xxx"` and `git config --global user.email "xxx@xxx"` before running this script.
   
## 2. Build

### Linux

Shelter adds a tiny modification for Linux kernel. To build the kernel, run `./scripts/linux_build.sh -s linux -p fvp all`


### Shelter Monitor

Run `./scripts/atf_build.sh` to build the firmware.

## 3. Run

### Lanuch FVP

Run `./scripts/bootfvp.sh` to lanuch the FVP and start the Linux.

The pure root filesystem will be initialized at first boot, so it will take about 10 minutes.

### Run App in Shelter 

- Compile Shelter driver and upload to FVP
```shell
    cd src/shelter_userland/shelter_driver
    make
    scp ./shelter_manager.ko root@192.168.122.33:~
```
- Load Shelter driver in FVP

```
 insmod shelter_manager.ko
```


- Using shelter_loader to run an application in Shelter as SApp. 

```shell
cd src/shelter_userland/shelter_loader
make
scp ./shelter_loader root@192.168.122.33:~

cd src/shelter_userland/shelter_loader/hello_world
make
scp ./hello_world root@192.168.122.33:~

#In FVP linux terminal, run 
./shelter_loader ./hello_world
```

**Notes**: This is a research software, so stuff may break. The prototype's purpose is to demonstrate that the original idea works. It is expected to have implementation issues, e.g., the current prototype only supports running statically compiled programs;
Crashes or GPF when running complex programs, especially multi-processes, may occur because not all system calls are handled. We would try to enhance functionality and fix implementation issues.

### Test multi-GPT memory isolation 
The multi-GPT memory isolation is Shelter's core machenism. It makes SApps still run in Normal world, but each SApp is isolated from other SApps and software in the Normal, Secure, and Realm World.

We provide an API `ENC_ISOLATION_TEST` in the `shelter_driver` to test the effectiveness of Shelter's memory isolation. The API is used to simulate to illegally access SApp's memory when the OS is compromised. By running `access_test` program to call API to make OS accessing the program's memory, a Granule Protection Fault (GPF) is invoked, indicating an access permission prohibition and effective isolation.

```shell
#manipulate Shelter driver to access the SApp memory region
cd src/shelter_userland/shelter_loader/access_test
make
scp ./access_test root@192.168.122.33:~
./shelter_loader ./access_test

#a Granule Protection Fault (GPF) is invoked, indicating an access permission prohibition
[ 2269.310914] SHELTER kernel Virt: 0xffffffc01a900000
[ 2269.310974] Unhandled fault at 0xffffffc01a900000
[ 2269.311036] Mem abort info:
[ 2269.311091]   ESR = 0x96000028
[ 2269.311148]   Exception class = DABT (current EL), IL = 32 bits
[ 2269.311234]   SET = 0, FnV = 0
[ 2269.311290]   EA = 0, S1PTW = 0
[ 2269.311348] Data abort info:
[ 2269.311390]   ISV = 0, ISS = 0x00000028
[ 2269.311434]   CM = 0, WnR = 0
```

## Publication

```
@inproceedings{zhang2023shelter,
  title={SHELTER: Extending Arm CCA with Isolation in User Space},
  author={Zhang, Yiming and Hu, Yuxin and Ning, Zhenyu and Zhang, Fengwei and Luo, Xiapu and Huang, Haoyang and Yan, Shoumeng and He, Zhengyu},
  booktitle={32nd USENIX Security Symposium (USENIX Security’23)},
  year={2023}
}
```







