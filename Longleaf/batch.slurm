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
evaluation/experiments/baselines_vs_PCGF.py