#!/bin/sh
#SBATCH --job-name=scenariogen
#SBATCH --cpus-per-task=12
#SBATCH -o %N-%x-%j.out # File to which STDOUT will be written
#SBATCH --gres=gpu:1
#SBATCH -p volta-gpu
#SBATCH --mem=16G
#SBATCH -t 00:05:00
#SBATCH --qos gpu_access

nvidia-smi

$ScenariogenDependencies/ScenarioGeneration/Singularity/run.sh \
SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
--ego-module evaluation.agents.TFPP \
--coverage-module traffic-rules