#!/bin/bash
#SBATCH --job-name=scenariogen-build
#SBATCH -o "%j-%N-%x.log"
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH --mem=16G
#SBATCH -t 1:00:00


apptainer build \
    --force \
    --nv \
    --bind ${ScenariogenDependencies}/carla/Dist/CARLA_Shipping_0.9.15-168-g20a4a4618-dirty/LinuxNoEditor:/home/scenariogen/carla \
    --bind ${ScenariogenDependencies}/Scenic_04-10-2024:/home/scenariogen/Scenic \
    --bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
    --bind ${ScenariogenDependencies}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
    --bind ${ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
    run.sif \
    build.singularity

