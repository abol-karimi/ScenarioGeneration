#!/usr/bin/env python3.8
import jsonpickle

import matplotlib
matplotlib.use('TkAgg')

from scenariogen.core.seed_generators import random as random_seed_generator

file_stem = '4way-stop_random'
config = {'scenario_path': f'experiments/seed_definitions/{file_stem}',
          'output_folder': f'experiments/seeds_{file_stem}',
          'render_ego': False,
          'render_spectator': False,
          'PRNG_seed': 0,
          'spline_degree': 3,
          'spline_knots_size': 50,
          'scene_maxIterations': 50,
          'simulate_maxIterations': 1,
          'seeds_num': 10,
          }

random_seed_generator.run(config)