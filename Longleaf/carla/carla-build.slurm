#!/bin/bash
#SBATCH --job-name=carla-build
#SBATCH -o "%j-%N-%x.txt"
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --exclude=g0301,g0304,g0305,g0311,g0313
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH --mem=16G
#SBATCH -t 10:00:00

singularity build \
    --force \
    --nv \
    carla-build.sif \
    carla-build.singularity

singularity run \
    --nv \
    --bind /users/a/b/abol/CarlaUnreal:/home/scenariogen/CarlaUnreal \
    --bind /users/a/b/abol/carla:/home/scenariogen/carla \
    carla-build.sif

# change the runscript
singularity build \
    --force \
    carla-run.sif \
    carla-run.singularity