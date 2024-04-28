#!/bin/bash
#SBATCH --job-name=scenariogen-run
#SBATCH -o "%j-%N-%x.log"
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH --mem=16G
#SBATCH -t 00:10:00

export dependencies=/users/a/b/abol && \
apptainer run \
    --nv \
    --bind $dependencies/carla/Dist/CARLA_Shipping_0.9.15-168-g20a4a4618-dirty/LinuxNoEditor:/home/scenariogen/carla \
    $dependencies/Longleaf/scenariogen/run.sif
