#!/bin/bash
#SBATCH --job-name=carla-build
#SBATCH -o "%j-%N-%x.txt"
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH --mem=16G
#SBATCH -t 10:00:00

singularity build \
    --force \
    --nv \
    ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/carla/build.sif \
    ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/carla/build.singularity

singularity run \
    --nv \
    --bind /users/a/b/abol/CarlaUnreal:/home/scenariogen/CarlaUnreal \
    --bind /users/a/b/abol/carla:/home/scenariogen/carla \
    ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/carla/build.sif

# change the runscript
singularity build \
    --force \
    ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/carla/run.sif \
    ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/carla/run.singularity