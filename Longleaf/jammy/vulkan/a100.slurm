#!/bin/bash
#SBATCH --job-name="a100-gpu"
#SBATCH -o "%x-%j-%N.log"
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=4G
#SBATCH --qos gpu_access
#SBATCH -p a100-gpu
#SBATCH --gres=gpu:1
#SBATCH -t 00:20:00

apptainer build \
    --force \
    --nv \
    v100-sxm2.sif \
    vulkan.singularity && \
apptainer run \
    --nv \
    v100-sxm2.sif \
    /home/scenariogen/ScenarioGeneration/Longleaf/nodes/system_info.sh

