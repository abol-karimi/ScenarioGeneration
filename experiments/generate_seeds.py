#!/usr/bin/env python3.8
import jsonpickle

import matplotlib
matplotlib.use('TkAgg')

from scenariogen.core.seed_generators import random as random_seed_generator

config = {'scenario_path': 'experiments/seed_definitions/Town05_intersection396_Autopilot_random',
          'output_folder': 'experiments/seeds_random',
          'render_ego': False,
          'render_spectator': True,
          'PRNG_seed': 0,
          'spline_degree': 3,
          'spline_knots_size': 50,
          'scene_maxIterations': 50,
          'simulate_maxIterations': 1,
          'seeds_num': 10,
          }

random_seed_generator.run(config)