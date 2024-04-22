#!/bin/sh
#SBATCH --job-name=SUT
#SBATCH -o %j-%N-%x.txt # File to which STDOUT will be written
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=20
#SBATCH --mem=16G
#SBATCH -t 00:10:00


singularity run \
    --nv \
    --bind ${ScenariogenDependencies}/carla/Dist/CARLA_Shipping_0.9.15-168-g20a4a4618-dirty/LinuxNoEditor:/home/scenariogen/carla \
    --bind ${ScenariogenDependencies}/Scenic_04-10-2024:/home/scenariogen/Scenic \
    --bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
    --bind ${ScenariogenDependencies}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
    --bind ${ScenariogenDependencies}/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
    --bind ${ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
    ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/scenariogen/run.sif \
    SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
        --ego-module evaluation.agents.TFPP \
        --coverage-module traffic-rules