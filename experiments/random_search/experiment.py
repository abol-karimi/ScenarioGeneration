#!/usr/bin/env python3.8

"""
Research question:
  How does the performance of Atheris compare to a random search?

"""

import jsonpickle
from pathlib import Path
from timeloop import Timeloop
from datetime import timedelta
import time

from scenariogen.core.seed_generators import random as random_seed_generator
from experiments.configs import coverage_config

if __name__ == '__main__':

  gen_ego = 'TFPP'
  coverage_module = 'traffic'

  config = {'scenario_path': f'experiments/seeds/random/definitions/4way-stop.scenic',
            'output_folder': f'experiments/random_search/output_{gen_ego}_{coverage_module}/fuzz-inputs',
            **coverage_config,
            'coverage_module': 'traffic',
            'coverages_folder': f'experiments/random_search/output_{gen_ego}_{coverage_module}/coverages',
            'simulator': 'carla',
            'render_spectator': False,
            'render_ego': False,
            'PRNG_seed': 0,
            'spline_degree': 3,
            'spline_knots_size': 50,
            'scene_maxIterations': 50,
            'simulate_maxIterations': 1,
            'max_total_time': 60*60, # seconds
            }
  
  fuzz_inputs_path = Path(config['output_folder'])
  bugs_path = fuzz_inputs_path.parents[0]/'bugs'
  coverages_path = Path(config['coverages_folder'])
  events_path = coverages_path.parents[0]/'events'

  # Decide to resume or start
  results_file = fuzz_inputs_path.parents[0]/'results.json'
  if results_file.is_file():
    print('Resume option not implemented yet!')
    exit(1)
  else:
    fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
    bugs_path.mkdir(parents=True, exist_ok=True)
    coverages_path.mkdir(parents=True, exist_ok=True)
    events_path.mkdir(parents=True, exist_ok=True)
    for path in fuzz_inputs_path.glob('*'):
      path.unlink()
    for path in bugs_path.glob('*'):
      path.unlink()
    for path in coverages_path.glob('*'):
      path.unlink()
    for path in events_path.glob('*'):
      path.unlink()
    coverages = set()
    results = []
    generator_state = None

  # Set up a measurement loop
  measurements = []
  tl = Timeloop()
  period = 60 # seconds
  @tl.job(interval=timedelta(seconds=period))
  def measure_progress():
    new_coverages = set(coverages_path.glob('*')) - coverages
    coverages.update(new_coverages)
    measurements.append({'exe_time': period,
                        'new_coverages': new_coverages,
                        })
    print(f'\nMeasurement recorded!\n')

  # try:
  tl.start(block=False)
  generator_state = random_seed_generator.run(config)
  # except Exception as e:
  #   print(f'Exception of type {type(e)} in random_search: {e}.')

  print(f'Measurement thread will stop in {period} seconds...')
  time.sleep(period)
  tl.stop()
  results.append({'measurements': measurements,
                  'generator_state': generator_state
                  })

  with open(results_file, 'w') as f:
    f.write(jsonpickle.encode(results, indent=1))
