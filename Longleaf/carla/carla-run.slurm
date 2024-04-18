#!/bin/bash
#SBATCH --job-name=carla-run
#SBATCH -o "%j-%N-%x.txt"
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --nodelist=g0311
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH --mem=16G
#SBATCH -t 01:00:00

singularity run \
    --nv \
    --bind /users/a/b/abol/carla/Dist/CARLA_Debug_0.9.15-166-gf22d49d78-dirty/LinuxNoEditor:/home/scenariogen/carla \
    carla-run.sif
