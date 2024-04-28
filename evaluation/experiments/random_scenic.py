#!/usr/bin/env python3

"""
Research question:
  Can we beat random search as a baseline?

"""


from scenariogen.core.seed_generators.scenic import RandomSeedGenerator
from evaluation.configs import get_experiment_config


def get_config(gen_ego, gen_coverage, randomizer_seed, seeds_folder, max_total_time, output_folder):
  config = get_experiment_config(gen_ego, gen_coverage, randomizer_seed, seeds_folder, max_total_time, output_folder)

  random_search_config = {
    'generator': RandomSeedGenerator,
    'SUT-config': {**config['SUT-config'],
                   'scenario-file': f'evaluation/seeds/random/definitions/4way-stop.scenic',
                   },
    'save-coverage-events': True,
    'spline-degree': 3,
    'scene-maxIterations': 50,
    'simulate-maxIterations': 1,
    }

  return {**config, **random_search_config}
