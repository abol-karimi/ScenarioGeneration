#!/usr/bin/env python3

from itertools import product, permutations
import os
import shutil

generators = ('PCGF', 'Random')
egos = ('autopilot', 'BehaviorAgent', 'TFPP')
randomizer_seeds = (0, 1, )
coverages = ('traffic-rules', )

# For RQ2, we only vary the ego between the test-case-generation trials and
# and the test-case-execution trials.
trials = product(generators, permutations(egos, r=2), randomizer_seeds, coverages)
STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')
results_dir = f'{STORE_BASE_DIR}/ScenarioGeneration/evaluation/results/RQ2'

for generator, (gen_ego, test_ego), randomizer_seed, coverage in trials:
    shutil.move(
        f'{results_dir}/{generator}_{gen_ego}_{coverage}/{randomizer_seed}/{test_ego}',
        f'{results_dir}/{generator}_{gen_ego}_{coverage}/{test_ego}/{randomizer_seed}')


