#!/bin/bash
#SBATCH --job-name="v100-sxm2"
#SBATCH -o "%x-%j-%N.log"
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=4G
#SBATCH --qos gpu_access
#SBATCH -p volta-gpu
#SBATCH --gres=gpu:tesla_v100-sxm2-16gb:1
#SBATCH -t 00:10:00

printf 'volta-gpu v100-SXM2 libc version:\n' && \
ldd --version

apptainer build \
    --force \
    --nv \
    v100-sxm2.sif \
    vulkan.singularity && \
apptainer run \
    --nv \
    v100-sxm2.sif \
    bash -c "
        printf 'libc version inside bionic container:\n'
        ldd --version
        "