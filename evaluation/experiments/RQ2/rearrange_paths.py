#!/usr/bin/env python3

from itertools import product, permutations
import os


def update(base_dir, generator, gen_ego, coverage, test_ego, randomizer_seed):
    # Specify the file path, old string, and new string
    file_path = f'{base_dir}/{generator}_{gen_ego}_{coverage}/{test_ego}/{randomizer_seed}/results.json'
    os.rename(file_path, file_path+'.old.json')

    old_string = f'"{randomizer_seed}",\n          "{test_ego}"'
    new_string = f'"{test_ego}",\n          "{randomizer_seed}"'

    with open(file_path+'.old.json', 'r') as file:
        file_contents = file.read()

    file_contents = file_contents.replace(old_string, new_string)

    with open(file_path, 'w') as file:
        file.write(file_contents)


if __name__ == '__main__':
    generators = ('Atheris', 'PCGF', 'Random', )
    egos = ('autopilot', 'BehaviorAgent', 'TFPP')
    coverages = ('traffic-rules', )
    randomizer_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, )

    new_trials = [
        ('Atheris', 'autopilot', 'TFPP', 0, ),
        ('Atheris', 'BehaviorAgent', 'TFPP', 4, ),
        ('PCGF', 'autopilot', 'BehaviorAgent', 0, ),
        ('PCGF', 'autopilot', 'BehaviorAgent', 8, ),
        ('PCGF', 'autopilot', 'TFPP', 4, ),
        ('PCGF', 'BehaviorAgent', 'TFPP', 7, ),
        ('Random', 'autopilot', 'BehaviorAgent', 9, ),
        ('Random', 'autopilot', 'TFPP', 4, ),
        ('Random', 'BehaviorAgent', 'autopilot', 1, ),
        ('Random', 'BehaviorAgent', 'TFPP', 0, ),
        ('Random', 'BehaviorAgent', 'TFPP', 1, ),
        ('Random', 'TFPP', 'autopilot', 9, ),
        ('Random', 'TFPP', 'BehaviorAgent', 1, ),
    ]

    # For RQ2, we only vary the ego between the test-case-generation trials and
    # and the test-case-execution trials.
    trials = product(generators, permutations(egos, r=2), coverages, randomizer_seeds)
    STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')
    results_dir = f'{STORE_BASE_DIR}/ScenarioGeneration/evaluation/results/RQ2'

    for generator, (gen_ego, test_ego), coverage, randomizer_seed in trials:
        if (generator, gen_ego, test_ego, randomizer_seed) in new_trials:
            continue
        update(results_dir, generator, gen_ego, coverage, test_ego, randomizer_seed)
