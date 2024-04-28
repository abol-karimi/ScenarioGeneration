#!/bin/bash

printf "Info inside sindularity:\n"

uname -a

find /usr/lib64 -name libvulkan.so* 2>/dev/null
find /usr/lib64 -name libGLX_nvidia.so* 2>/dev/null

for f in `ls /usr/share/vulkan/icd.d/*.json`; do
    printf $f:\n
    cat $f
    printf '\n'
done

vulkaninfo