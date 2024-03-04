#!/bin/sh
#SBATCH --job-name=scenariogen
#SBATCH --cpus-per-task=1
#SBATCH -o %N-%x-%j.out # File to which STDOUT will be written
#SBATCH --gres=gpu:1
#SBATCH -p gpu,volta-gpu,a100-gpu
#SBATCH --mem=16G
#SBATCH -t 00:05:00
#SBATCH --qos gpu_access

DependencyFolder=/users/a/b/abol \
/users/a/b/abol/ScenarioGeneration/Singularity/run.sh \
/users/a/b/abol/ScenarioGeneration/Singularity/scenariogen.sif \
-c evaluation/experiments/baselines_vs_PCGF.py