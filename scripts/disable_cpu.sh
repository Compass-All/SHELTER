#!/bin/bash

number=$1
number=$((number-1))

for i in 1 2 3 4 5; do
    echo 0 > /sys/devices/system/cpu/cpu$i/online
done