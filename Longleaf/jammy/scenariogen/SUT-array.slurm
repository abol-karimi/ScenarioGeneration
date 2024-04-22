#!/bin/sh
#SBATCH --job-name=SUT-array
#SBATCH -o %j-%N-%x.txt # File to which STDOUT will be written
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --nodelist=dgx01
#SBATCH --ntasks=2
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:2,myJob:1
#SBATCH --cpus-per-task=12
#SBATCH --gpus-per-task=1
#SBATCH --mem=32G
#SBATCH -t 3-00:03:00
#SBATCH --array=0-1

singularity run \
    --nv \
    --bind $1/CARLA_0.9.15:/home/scenariogen/carla \
    --bind $1/Scenic_10-03-2023:/home/scenariogen/Scenic \
    --bind $1/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
    --bind $1/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
    --bind $1/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
    --bind $1/carla_garage_fork:/home/scenariogen/carla_garage_fork \
    $1/ScenarioGeneration/Longleaf/Singularity/scenariogen.sif \
    SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
    --ego-module evaluation.agents.TFPP \
    --coverage-module traffic-rules