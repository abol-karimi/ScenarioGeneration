#!/bin/sh
#SBATCH --job-name=SUT
#SBATCH -o %j-%x.txt
#SBATCH -p a100-gpu
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=16G
#SBATCH --qos gpu_access
#SBATCH --gres=gpu:1
#SBATCH -t 00:10:00

# volta-gpu:
#     tesla_v100-sxm2-16gb : 56
#     tesla_v100_16G : 32
# a100-gpu:
#     nvidia_a100-pcie-40gb : 24

echo `scontrol show jobid $SLURM_JOB_ID -dd | grep IDX` && \
nvidia-smi && \
export CARLA_Jammy_Dist=/work/users/a/b/abol/jammy/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor && \
export ScenariogenDependencies=/users/a/b/abol && \
apptainer run \
--nv \
--env CARLA_BINARY=CarlaUE4-Linux-Shipping \
--bind ${CARLA_Jammy_Dist}:/home/scenariogen/carla \
--bind ${ScenariogenDependencies}/Scenic_04-10-2024:/home/scenariogen/Scenic \
--bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
--bind ${ScenariogenDependencies}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
--bind ${ScenariogenDependencies}/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
--bind ${ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
${ScenariogenDependencies}/ScenarioGeneration/Longleaf/jammy/scenariogen/run.sif \
SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
    --ego-module evaluation.agents.autopilot \
    --coverage-module traffic-rules