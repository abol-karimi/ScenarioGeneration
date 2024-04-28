#!/bin/bash
#SBATCH --job-name="SUT-docker"
#SBATCH -o "%x-%j-%N.log"
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=5G
#SBATCH --qos gpu_access
#SBATCH -p volta-gpu
#SBATCH --gres=gpu:tesla_v100-sxm2-16gb:1
#SBATCH -t 01:00:00

module add apptainer/1.3.0-1

apptainer run \
    --nv \
    -e \
    /work/users/a/b/abol/carla-0.9.15.sif \
    /home/carla/CarlaUE4.sh \
        -RenderOffScreen \
        -nosound