#!/usr/bin/env python3.8
from scenariogen.core.seed_generators import random as random_seed_generator

config = {'scenario_path': f'experiments/seeds/random/definitions/4way-stop.scenic',
          'output_folder': f'experiments/seeds/random/seeds',
          'coverage_module': None,
          'simulator': 'carla',
          'render_spectator': False,
          'render_ego': False,
          'PRNG_seed': 0,
          'spline_degree': 3,
          'spline_knots_size': 50,
          'scene_maxIterations': 50,
          'simulate_maxIterations': 1,
          'max-total-time': 5*60,
          }

random_seed_generator.run(config)