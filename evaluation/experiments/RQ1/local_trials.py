#!/usr/bin/env python3

import subprocess
from itertools import product
from datetime import timedelta
import os

generators = ('Random', 'PCGF', )
egos = ('TFPP', 'autopilot', 'BehaviorAgent', )
randomizer_seeds = (0, 1, )
trials = product(generators, egos, randomizer_seeds)
trial_timeout = timedelta(minutes=10)

BASE_IMAGE_DIST='bionic'
CARLA_BUILD_CONFIG='Shipping'
CARLA_BUILD_NUMBER='0.9.15-187-g7a540559a'
SCENIC_VERSION='Scenic_05-03-2024'
Z3_VERSION='z3-4.12.6-x64-glibc-2.31'

WORK_BASE_DIR=os.environ.get('WORK_BASE_DIR')
STORE_BASE_DIR=os.environ.get('STORE_BASE_DIR')
CARLA_DIST=f'{WORK_BASE_DIR}/{BASE_IMAGE_DIST}/carla/Dist/CARLA_{CARLA_BUILD_CONFIG}_{CARLA_BUILD_NUMBER}/LinuxNoEditor'
CARLA_BINARY=f'CarlaUE4-Linux-{CARLA_BUILD_CONFIG}'
SCENARIOGEN_DEPENDENCIES=STORE_BASE_DIR


for generator, ego, randomizer_seed in trials:
    cmd = f'''
        apptainer run \
            --nv \
            --cleanenv \
            --bind {CARLA_DIST}:/home/scenariogen/carla \
            --bind {SCENARIOGEN_DEPENDENCIES}/{SCENIC_VERSION}:/home/scenariogen/Scenic \
            --bind {SCENARIOGEN_DEPENDENCIES}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
            --bind {SCENARIOGEN_DEPENDENCIES}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
            --bind {SCENARIOGEN_DEPENDENCIES}/{Z3_VERSION}:/home/scenariogen/z3 \
            --bind {SCENARIOGEN_DEPENDENCIES}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
            {SCENARIOGEN_DEPENDENCIES}/ScenarioGeneration/Apptainer/images/scenariogen-{BASE_IMAGE_DIST}.sif \
                evaluation/experiments/RQ1/trial.py \
                    --generator {generator} \
                    --ego {ego} \
                    --randomizer-seed {randomizer_seed} \
                    --coverage traffic-rules \
                    --seconds {trial_timeout.total_seconds()}
        "
    '''
    subprocess.run(cmd, shell=True)

