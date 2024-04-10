#!/bin/sh
#SBATCH --job-name=Carla-array
#SBATCH -o %j-%N-%x.out # File to which STDOUT will be written
#SBATCH -p volta-gpu
#SBATCH -t 00:02:00
#SBATCH --nodes=1
#SBATCH --nodelist=g0316
#SBATCH --ntasks=2
#SBATCH --cpus-per-task=12
#SBATCH --mem=18G
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:2
#SBATCH --gpus-per-task=1
#SBATCH --array=0-1


srun singularity run \
    --nv \
    --env carla_egg=carla-0.9.15-py3.7-linux-x86_64.egg \
    --bind $1/CARLA_0.9.15:/home/scenariogen/carla \
    --bind $1/Scenic_10-03-2023:/home/scenariogen/Scenic \
    --bind $1/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
    --bind $1/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
    --bind $1/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
    --bind $1/carla_garage_fork:/home/scenariogen/carla_garage_fork \
    $1/ScenarioGeneration/Singularity/scenariogen.sif \
    /home/scenariogen/carla/CarlaUE4/Binaries/Linux/CarlaUE4-Linux-Shipping \
        CarlaUE4 \
        -nosound \
        -RenderOffScreen \
        -carla-rpc-port=0 \
        -carla-streaming-port=0 \
        -carla-secondary-port=0