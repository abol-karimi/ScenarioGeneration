#!/usr/bin/env python3.8
import jsonpickle

from scenariogen.core.seed_generators import random as random_seed_generator

seconds = 20
timestep = .05

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprints = jsonpickle.decode(f.read())

config = {'scenario_path': 'experiments/seeds_definitions/Town05_intersection396_random',
          'output_folder': 'experiments/seeds_random',
          'steps': int(seconds // timestep),
          'timestep': timestep,
          'render': False,
          'prng_seed': 0,
          'spline_degree': 3,
          'spline_knots_size': 50,
          'scene_maxIterations': 50,
          'simulate_maxIterations': 1,
          'seeds_num': 50,
          }

random_seed_generator.run(config)