#!/usr/bin/env python3

import subprocess
from itertools import product
from datetime import timedelta
import os

experiments = ('PCGF', 'Random')
egos = ('autopilot', 'BehaviorAgent', 'TFPP')
seeds_folder = 'evaluation/seeds/random/seeds'
randomizer_seeds = (0, 1, )
coverages = ('traffic-rules', )
trial_timeout = timedelta(minutes=10)

# dependent variables
trials = product(experiments, egos, randomizer_seeds, coverages)
STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')

for experiment, ego, randomizer_seed, coverage in trials:
    cmd = f'''
        {STORE_BASE_DIR}/ScenarioGeneration/Apptainer/scripts.sh scenariogen_run bionic Shipping \
            evaluation/experiments/RQ1/trial.py \
            --experiment {experiment} \
            --ego {ego} \
            --randomizer-seed {randomizer_seed} \
            --seeds-folder {seeds_folder} \
            --coverage {coverage} \
            --seconds {trial_timeout.total_seconds()} \
            --output-folder evaluation/results/RQ1/{experiment}_{ego}_{coverage}/{randomizer_seed} \
            --process-name RQ1_{experiment}_{ego}_{randomizer_seed}
    '''
    subprocess.run(cmd, shell=True)

