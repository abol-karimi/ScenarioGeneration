#!/usr/bin/env python3

from itertools import product, permutations
import os
import shutil

generators = ('Atheris', 'PCGF', 'Random', )
egos = ('autopilot', 'BehaviorAgent', 'TFPP')
coverages = ('traffic-rules', )
randomizer_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, )

# For RQ2, we only vary the ego between the test-case-generation trials and
# and the test-case-execution trials.
trials = product(generators, permutations(egos, r=2), coverages, randomizer_seeds)
STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')
results_dir = f'{STORE_BASE_DIR}/ScenarioGeneration/evaluation/results/RQ2'

for generator, (gen_ego, test_ego), coverage, randomizer_seed in trials:
    shutil.move(
        f'{results_dir}/{generator}_{gen_ego}_{coverage}/{randomizer_seed}/{test_ego}',
        f'{results_dir}/{generator}_{gen_ego}_{coverage}/{test_ego}/{randomizer_seed}')


