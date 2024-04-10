#!/bin/sh
#SBATCH --job-name=SUT
#SBATCH -o %j-%N-%x.out # File to which STDOUT will be written
#SBATCH -p volta-gpu
#SBATCH -t 00:03:00
#SBATCH --nodes=1
#SBATCH --nodelist=g0313
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=12
#SBATCH --mem=16G


singularity run --nv \
--env carla_egg=carla-0.9.15-py3.7-linux-x86_64.egg \
--bind $1/CARLA_0.9.15:/home/scenariogen/carla \
--bind $1/Scenic_10-03-2023:/home/scenariogen/Scenic \
--bind $1/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
--bind $1/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
--bind $1/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
--bind $1/carla_garage_fork:/home/scenariogen/carla_garage_fork \
$1/ScenarioGeneration/Singularity/scenariogen.sif \
SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
--ego-module evaluation.agents.autopilot \
--coverage-module traffic-rules