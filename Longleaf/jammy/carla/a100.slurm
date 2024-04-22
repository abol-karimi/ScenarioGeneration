#!/bin/bash
#SBATCH --job-name="a100"
#SBATCH -o "%x-%j-%N.txt"
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=10
#SBATCH --mem=10G
#SBATCH --qos gpu_access
#SBATCH -p a100-gpu
#SBATCH --gres=gpu:1
#SBATCH -t 02:00:00

# a100-gpu: nvidia_a100-pcie-40gb

NvidiaDriver=$1 && \
printf "Image: $NvidiaDriver \n" && \
printf "Partion: $SLURM_JOB_PARTITION \n" && \
printf "Resource allocation: \n" && \
printf "\t `scontrol show jobid $SLURM_JOB_ID -dd | grep IDX` \n" && \
nvidia-smi && \
./scripts.sh build_image $NvidiaDriver && \
./scripts.sh run_carla $NvidiaDriver