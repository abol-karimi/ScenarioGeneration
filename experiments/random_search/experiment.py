#!/usr/bin/env python3.8

"""
Research question:
  Can we beat random search as a baseline?

"""
from random import Random

from scenariogen.core.seed_generators.random import RandomSeedGenerator
from experiments.configs import coverage_config
from experiments.runner import run


def get_config(gen_ego, gen_coverage, randomizer_seed, max_total_time, output_folder):
  config_randomizer = Random(randomizer_seed)
  config_seed_range = 1000

  if gen_ego in {'TFPP', 'autopilot', None}:
    simulator = 'carla'
  elif gen_ego in {'intersectionAgent'}:
    simulator = 'newtonian'
  else:
    print(f'Are you sure you want to include agent {gen_ego} in the experiments?')
    exit(1)

  config = {
    'generator': RandomSeedGenerator,
    'results-file': f'{output_folder}/{gen_ego}_{gen_coverage}/results.json',
    'scenario-file': f'experiments/seeds/random/definitions/4way-stop.scenic',
    'fuzz-inputs-folder': f'{output_folder}/fuzz-inputs',
    'events-folder': f'{output_folder}/{gen_ego}_{gen_coverage}/events',
    'bugs-folder': f"{output_folder}/{gen_ego}_{gen_coverage}/bugs",
    **coverage_config,
    'coverage_module': gen_coverage,
    'save-coverage-events': True,
    'simulator': simulator,
    'render-spectator': False,
    'render-ego': False,
    'randomizer-seed': config_randomizer.randrange(config_seed_range),
    'spline-degree': 3,
    'spline-knots-size': 50,
    'scene-maxIterations': 50,
    'simulate-maxIterations': 1,
    'max-total-time': max_total_time, # seconds
    }
  
  return config

if __name__ == '__main__':
  gen_ego = 'TFPP'
  gen_coverage = 'traffic-rules'
  randomizer_seed = 0
  max_total_time = 4*60*60
  output_folder = f'experiments/random_search/{gen_ego}_{gen_coverage}_{randomizer_seed}_{max_total_time}'

  config = get_config(gen_ego, gen_coverage, randomizer_seed, max_total_time, output_folder)

  run(config)
