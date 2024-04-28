#!/bin/bash
#SBATCH --job-name=carla-run
#SBATCH -o "%j-%N-%x.log"
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=10
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH --mem=10G
#SBATCH -t 00:10:00


echo `scontrol show jobid $SLURM_JOB_ID -dd | grep IDX` && \
nvidia-smi && \
export CARLA_DIST=CARLA_0.9.15 && \
export CARLA_BINARY=CarlaUE4-Linux-Shipping && \
apptainer run \
    --nv \
    --bind ${ScenariogenDependencies}/${CARLA_DIST}:/home/scenariogen/carla \
    ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/CARLA_0.9.15/jammy.sif
