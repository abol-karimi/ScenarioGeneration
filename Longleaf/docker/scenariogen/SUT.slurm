#!/bin/sh
#SBATCH --job-name=SUT
#SBATCH -o "%x-%j-%N.log"
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=16G
#SBATCH --qos gpu_access
#SBATCH -p volta-gpu
#SBATCH --gres=gpu:tesla_v100-sxm2-16gb:1
#SBATCH -t 00:30:00

module add apptainer/1.3.0-1

apptainer run \
    --nv \
    --bind ${ScenariogenDependencies}/carla/Dist/CARLA_Shipping_0.9.15-168-g20a4a4618-dirty/LinuxNoEditor:/home/scenariogen/carla \
    --bind ${ScenariogenDependencies}/Scenic_04-10-2024:/home/scenariogen/Scenic \
    --bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
    --bind ${ScenariogenDependencies}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
    --bind ${ScenariogenDependencies}/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
    --bind ${ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
    image.sif \
    SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
        --ego-module evaluation.agents.TFPP \
        --coverage-module traffic-rules