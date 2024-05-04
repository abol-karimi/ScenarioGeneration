#!/usr/bin/env python3

import subprocess
from itertools import product
from datetime import timedelta
import os

generators = ('Random', 'Atheris', 'PCGF', )
egos = ('autopilot', 'TFPP', )
randomizer_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, )
trials = product(generators, egos, randomizer_seeds)
trial_timeout = timedelta(hours=24)
slurm_timeout = trial_timeout + timedelta(minutes=30)
ScenariogenDependencies = os.environ.get('STORE_BASE_DIR')
CARLA_Dist = f"{os.environ.get('STORE_BASE_DIR')}/bionic/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor"
SCENIC_Version='Scenic_04-10-2024'
Z3_Version='z3-4.12.6-x64-glibc-2.35'
Ubuntu_Dist='bionic'

for generator, ego, randomizer_seed in trials:
    cmd = f'''
        sbatch \
        --mail-type=FAIL \
        --mail-user=ak@cs.unc.edu \
        --job-name={generator}_{randomizer_seed} \
        -o "%x-%j-%N.log" \
        --nodes=1 \
        --ntasks=1 \
        --cpus-per-task=8 \
        --mem=20G \
        --qos gpu_access \
        -p volta-gpu \
        --gres=gpu:tesla_v100-sxm2-16gb:1 \
        -t {slurm_timeout.days}-{slurm_timeout.seconds//3600}:{(slurm_timeout.seconds%3600)//60}:{slurm_timeout.seconds%60} \
        --wrap="\
            module add apptainer/1.3.0-1; \
            apptainer run \
                --net \
                --network=none \
                --nv \
                --cleanenv \
                --bind {CARLA_Dist}:/home/scenariogen/carla \
                --bind {ScenariogenDependencies}/{SCENIC_Version}:/home/scenariogen/Scenic \
                --bind {ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
                --bind {ScenariogenDependencies}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
                --bind {ScenariogenDependencies}/{Z3_Version}:/home/scenariogen/z3 \
                --bind {ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
                {ScenariogenDependencies}/ScenarioGeneration/Apptainer/images/scenariogen-{Ubuntu_Dist}.sif \
                    evaluation/experiments/RQ1/trial.py \
                        --generator {generator} \
                        --ego {ego} \
                        --randomizer-seed {randomizer_seed} \
                        --coverage traffic-rules \
                        --seconds {trial_timeout.total_seconds()}
            "
    '''
    subprocess.Popen(cmd, shell=True)

