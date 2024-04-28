#!/usr/bin/env python3
from scenariogen.core.seed_generators import random as random_seed_generator
from evaluation.configs import coverage_config

config = {'scenario-file': f'experiments/seeds/random/definitions/4way-stop.scenic',
          'fuzz-inputs-folder': f'experiments/seeds/random/seeds',
          'simulator': 'carla',
          'render-spectator': False,
          'render-ego': False,
          'PRNG-seed': 0,
          'spline-degree': 3,
          'scene-maxIterations': 50,
          'simulate-maxIterations': 1,
          'max-total-time': 20*60, # seconds
          }

random_seed_generator.run(config)