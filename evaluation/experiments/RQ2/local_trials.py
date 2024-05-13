#!/usr/bin/env python3

import subprocess
from itertools import product, permutations
from datetime import timedelta
import os

generators = ('PCGF', 'Random')
egos = ('autopilot', 'BehaviorAgent', 'TFPP')
randomizer_seeds = (0, 1, )
coverages = ('traffic-rules', )
trial_timeout = timedelta(minutes=10) # the same as the time budget for generating the test cases

# For RQ2, we only vary the ego between the test-case-generation trials and
# and the test-case-execution trials.
trials = product(generators, permutations(egos, r=2), randomizer_seeds, coverages)
STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')

for generator, (gen_ego, test_ego), randomizer_seed, coverage in trials:
    cmd = f'''
        {STORE_BASE_DIR}/ScenarioGeneration/Apptainer/scripts.sh scenariogen_run bionic Shipping \
            evaluation/experiments/RQ2/trial.py \
            --ego {test_ego} \
            --seeds-folder evaluation/results/RQ1/{generator}_{gen_ego}_{coverage}/{randomizer_seed}/fuzz-inputs \
            --coverage {coverage} \
            --seconds {trial_timeout.total_seconds()} \
            --output-folder evaluation/results/RQ2/{generator}_{gen_ego}_{coverage}/{test_ego}/{randomizer_seed}
    '''
    completed_proc = subprocess.run(cmd, shell=True)
    print(f'Completed trial {generator}_{gen_ego}_{coverage}_{randomizer_seed}_{test_ego} with exit code: {completed_proc.returncode}')

