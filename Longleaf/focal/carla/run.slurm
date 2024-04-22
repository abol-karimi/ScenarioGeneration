#!/bin/bash
#SBATCH --job-name=carla-focal
#SBATCH -o "%j-%N.txt"
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:tesla_v100_16G:1
#SBATCH --mem=8G
#SBATCH -t 00:05:00

# volta-gpu:
#    tesla_v100-sxm2-16gb
#    tesla_v100_16G
# a100-gpu:
#    nvidia_a100-pcie-40gb


echo `scontrol show jobid $SLURM_JOB_ID -dd | grep IDX` && \
nvidia-smi && \
export CARLA_DIST=carla/Dist/CARLA_Shipping_0.9.15-168-g20a4a4618-dirty/LinuxNoEditor && \
export CARLA_BINARY=CarlaUE4-Linux-Shipping && \
singularity run \
    --nv \
    --bind ${ScenariogenDependencies}/${CARLA_DIST}:/home/scenariogen/carla \
    ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/focal/carla/run.sif
