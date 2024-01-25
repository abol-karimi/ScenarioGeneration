#!/usr/bin/env python3.8

"""
Research question:
  Can we beat random search as a baseline?

"""
from random import Random

from scenariogen.core.seed_generators.random import RandomSeedGenerator
from experiments.configs import coverage_config
from experiments.runner import run

gen_ego = 'TFPP'
gen_coverage = 'traffic-rules'
config_randomizer_seed = 0
config_randomizer = Random(config_randomizer_seed)
config_seed_range = 1000

config = {
  'generator': RandomSeedGenerator,
  'results-file': f'experiments/random_search/gen_{gen_ego}_{gen_coverage}/results.json',
  'scenario-file': f'experiments/seeds/random/definitions/4way-stop.scenic',
  'fuzz-inputs-folder': f'experiments/random_search/gen_{gen_ego}_{gen_coverage}/fuzz-inputs',
  'bugs-folder': f"experiments/random_search/gen_{gen_ego}_{gen_coverage}/test_{gen_ego}_{gen_coverage}/bugs",
  **coverage_config,
  'coverage_module': gen_coverage,
  'save-coverage-events': True,
  'events-folder': f'experiments/random_search/gen_{gen_ego}_{gen_coverage}/test_{gen_ego}_{gen_coverage}/events',
  'simulator': 'carla',
  'render-spectator': False,
  'render-ego': False,
  'randomizer-seed': config_randomizer.randrange(config_seed_range),
  'spline-degree': 3,
  'spline-knots-size': 50,
  'scene-maxIterations': 50,
  'simulate-maxIterations': 1,
  'max-total-time': 4*60*60, # seconds
  }

if __name__ == '__main__':  
  run(config)
