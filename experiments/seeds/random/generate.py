#!/usr/bin/env python3.8
import jsonpickle

from scenariogen.core.seed_generators import random as random_seed_generator

file_stem = '4way-stop_autopilot'
config = {'scenario_path': f'experiments/seeds/random/definitions/{file_stem}',
          'output_folder': f'experiments/seeds/random/seeds/{file_stem}',
          'simulator': 'carla',
          'render_spectator': True,
          'render_ego': False,
          'PRNG_seed': 0,
          'spline_degree': 3,
          'spline_knots_size': 50,
          'scene_maxIterations': 50,
          'simulate_maxIterations': 1,
          'max_total_time': 60,
          }

random_seed_generator.run(config)