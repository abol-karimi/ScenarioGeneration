#!/bin/bash


printf "Partion: $SLURM_JOB_PARTITION \n" && \
printf "Resource allocation: \n" && \
printf "\t `scontrol show jobid $SLURM_JOB_ID -dd | grep IDX` \n" && \

uname -a

# Show the host's libc version, shouldn't be older than the libc inside the container
ldd --version

for f in `ls /usr/share/vulkan/icd.d/*.json`; do
    printf $f:\n
    cat $f
    printf '\n'
done

find /usr/lib64 -name libvulkan.so* 2>/dev/null
find /usr/lib64 -name libGLX_nvidia.so* 2>/dev/null