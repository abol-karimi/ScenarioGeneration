#!/bin/bash
#SBATCH --job-name=scenariogen
#SBATCH --cpus-per-task=1
#SBATCH -o %x-%j.out # File to which STDOUT will be written
#SBATCH -e %x-%j.err # File to which STDERR will be written
#SBATCH --gres=gpu:1
#SBATCH -p volta-gpu
#SBATCH --mem=16G
#SBATCH -t 00:05:00
#SBATCH --qos gpu_access
python ~/ScenarioGeneration/experiments/baseline_vs_PCGF.py

singularity exec --bind /users/a/b/abol/RCtest:/data trinityrnaseq.simg Trinity --seqType fq --left /data/Bavi_F_4_1.fq --right /data/Bavi_F_4_2.fq --output /data/TrinityOut --max_memory 20G