#!/bin/bash
# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source $SCRIPT_DIR/config.sh 

DST=$THIRD_PARTY_DIR/$TF_A_DIR


unlink $DST
echo "/Path/to/this/repo/SHELTER/shelter_monitor => $DST"
ln -s $SRC_DIR/$TF_A_DIR $THIRD_PARTY_DIR/$TF_A_DIR
