#!/bin/bash
#SBATCH --job-name="a100-gpu"
#SBATCH -o "%x-%j-%N.log"
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=1G
#SBATCH --qos gpu_access
#SBATCH -p a100-gpu
#SBATCH --gres=gpu:1
#SBATCH -t 00:02:00


printf 'a100-gpu libc version:\n' && \
ldd --version

apptainer build \
    --force \
    --nv \
    a100.sif \
    vulkan.singularity && \
apptainer run \
    --nv \
    a100.sif \
    bash -c "
        printf 'libc version inside bionic container:\n'
        ldd --version
        "

