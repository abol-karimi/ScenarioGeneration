#!/bin/bash
#SBATCH --job-name="v100-sxm2"
#SBATCH -o "%x-%j-%N.log"
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=4G
#SBATCH --qos gpu_access
#SBATCH -p volta-gpu
#SBATCH --gres=gpu:tesla_v100-sxm2-16gb:1
#SBATCH -t 00:30:00

ScenariogenDependencies=/users/a/b/abol

#${ScenariogenDependencies}/ScenarioGeneration/Longleaf/nodes/info_node.sh

ls /usr/lib64 | grep vulkan

apptainer build \
    --force \
    --nv \
    v100-sxm2.sif \
    vulkan.singularity && \
apptainer run \
    --nv \
    --bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
    v100-sxm2.sif

    #/home/scenariogen/ScenarioGeneration/Longleaf/nodes/info_singularity.sh

