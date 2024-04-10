#!/bin/sh
#SBATCH --job-name=carla
#SBATCH -o %j-%N-%x.out # File to which STDOUT will be written
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=12
#SBATCH --mem=16G
#SBATCH -t 00:02:00

srun $1/CARLA_0.9.15/CarlaUE4/Binaries/Linux/CarlaUE4-Linux-Shipping \
    CarlaUE4 \
    -nosound \
    -RenderOffScreen \
    -prefernvidia \
    -carla-rpc-port=0 \
    -carla-streaming-port=0 \
    -carla-secondary-port=0