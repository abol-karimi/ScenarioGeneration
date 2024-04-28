#!/bin/bash
#SBATCH --job-name="v100-sxm2"
#SBATCH -o "%x-%j-%N.log"
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=10
#SBATCH --mem=10G
#SBATCH --qos gpu_access
#SBATCH -p volta-gpu
#SBATCH --gres=gpu:tesla_v100-sxm2-16gb:1
#SBATCH -t 02:00:00

# volta-gpu:
#    tesla_v100-sxm2-16gb
#    tesla_v100_16G

NvidiaDriver=$1 && \
printf "Image: $NvidiaDriver \n" && \
printf "Partion: $SLURM_JOB_PARTITION \n" && \
printf "Resource allocation: \n" && \
printf "\t `scontrol show jobid $SLURM_JOB_ID -dd | grep IDX` \n" && \
nvidia-smi && \
./scripts.sh build_image $NvidiaDriver && \
./scripts.sh run_carla $NvidiaDriver
