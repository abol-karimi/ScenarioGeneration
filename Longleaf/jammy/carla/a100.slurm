#!/bin/bash
#SBATCH --job-name="a100"
#SBATCH -o "%x-%j-%N.log"
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=20
#SBATCH --mem=20G
#SBATCH --qos gpu_access
#SBATCH -p a100-gpu
#SBATCH --gres=gpu:nvidia_a100-pcie-40gb:1
#SBATCH -t 02:00:00

# a100-gpu: nvidia_a100-pcie-40gb

NvidiaDriver=$1 && \
printf "Image: $NvidiaDriver \n" && \
nvidia-smi && \
./scripts.sh build_image $NvidiaDriver && \
./scripts.sh run_carla $NvidiaDriver