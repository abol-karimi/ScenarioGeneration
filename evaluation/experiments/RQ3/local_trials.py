#!/usr/bin/env python3

import subprocess
from itertools import product
from datetime import timedelta
import os


baseline_experiment = 'PCGF'
baseline_egos = ('TFPP', )
baseline_coverages = ('traffic-rules', )
baseline_dir = f'evaluation/results/RQ1'

test_experiment = 'PCGF_precheck'
test_egos = (None, )
test_coverages = ('trivial', )
test_dir = f'evaluation/results/RQ3'

seeds_folder = 'evaluation/seeds/random/seeds'
randomizer_seeds = (2, 3)
trial_timeout = timedelta(hours=2)

# dependent variables
baselines = tuple(product(baseline_egos, baseline_coverages))
tests = tuple(product(test_egos, test_coverages))
trials = tuple(product(baselines, tests, randomizer_seeds))
STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')

for baseline, test, randomizer_seed in trials:
    baseline_ego, baseline_coverage = baseline
    test_ego, test_coverage = test
    cmd = f'''
        {STORE_BASE_DIR}/ScenarioGeneration/Apptainer/scripts.sh scenariogen_run bionic Shipping \
            evaluation/experiments/RQ3/trial.py \
            --experiment {test_experiment} \
            {('--precheck-ego ' + test_ego) if test_ego else ''} \
            --precheck-coverage {test_coverage} \
            --ego {baseline_ego} \
            --randomizer-seed {randomizer_seed} \
            --seeds-folder {seeds_folder} \
            --coverage {baseline_coverage} \
            --seconds {trial_timeout.total_seconds()} \
            --output-folder {test_dir}/{baseline_experiment}_{baseline_ego}_{baseline_coverage}/{test_experiment}_{test_ego}_{test_coverage}/{randomizer_seed} \
            --process-name RQ3_{test_experiment}_{test_ego}_{test_coverage}_{randomizer_seed}
    '''
    subprocess.run(cmd, shell=True)

