#!/bin/sh
#SBATCH --job-name=RQ1
#SBATCH -p volta-gpu
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --mem=16G
#SBATCH --qos gpu_access
#SBATCH --gpus-per-node=1
#SBATCH --cpus-per-task=12
#SBATCH -t 00:30:00
#SBATCH --array=0-9

scenariogen_dependencies=$1

declare -i trial_timeout=20*60
generators=('PCGF' 'Random')
trial_seeds=(0 1 2 3 4)
trials=${#trial_seeds[@]}

declare -i id=$SLURM_ARRAY_TASK_ID
generator=${generators[ id / trials ]}
trial_seed=${trial_seeds[ id % trials ]}

srun \
    -o %x-%N-${generator}-${trial_seed}.out \
    singularity run --nv \
    --env carla_egg=carla-0.9.15-py3.7-linux-x86_64.egg \
    --bind ${scenariogen_dependencies}/CARLA_0.9.15:/home/scenariogen/carla \
    --bind ${scenariogen_dependencies}/Scenic_10-03-2023:/home/scenariogen/Scenic \
    --bind ${scenariogen_dependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
    --bind ${scenariogen_dependencies}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
    --bind ${scenariogen_dependencies}/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
    --bind ${scenariogen_dependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
    ${scenariogen_dependencies}/ScenarioGeneration/Singularity/scenariogen.sif \
    evaluation/experiments/RQ1/trial.py \
    --generator ${generator} \
    --ego TFPP \
    --randomizer-seed ${trial_seed} \
    --coverage traffic-rules \
    --seconds ${trial_timeout}

