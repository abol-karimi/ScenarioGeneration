#!/bin/bash
#SBATCH --job-name=scenariogen-run
#SBATCH -o "%j-%N-%x.log"
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=16G
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH -t 00:10:00

# tesla_v100-sxm2-16gb
# tesla_v100_16G

export CARLA_Jammy_Dist=/work/users/a/b/abol/jammy/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor && \
export ScenariogenDependencies=/users/a/b/abol && \
apptainer run \
    --nv \
    --bind ${CARLA_Jammy_Dist}:/home/scenariogen/carla \
    ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/jammy/scenariogen/run.sif
