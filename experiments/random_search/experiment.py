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


if __name__ == '__main__':

  experiment_type = 'random_search'
  experiment_name = '4way-stop_random'

  config = {'scenario_path': f'experiments/seed_definitions/{experiment_name}',
            'output_folder': f'experiments/{experiment_type}/output_{experiment_name}',
            'simulator': 'carla',
            'render_ego': False,
            'render_spectator': False,
            'PRNG_seed': 0,
            'spline_degree': 3,
            'spline_knots_size': 50,
            'scene_maxIterations': 50,
            'simulate_maxIterations': 1,
            'seeds_num': 10,
            }
  
  output_path = Path(config['output_folder'])
  fuzz_inputs_path = output_path/'fuzz-inputs'
  bugs_path = output_path/'bugs'

  # Decide to resume or start
  results_file = output_path/'results.json'
  if results_file.is_file():
    print('Resume option not implemented yet!')
    exit(1)
  else:
    fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
    bugs_path.mkdir(parents=True, exist_ok=True)
    for path in fuzz_inputs_path.glob('*'):
      path.unlink()
    for path in bugs_path.glob('*'):
      path.unlink()
    fuzz_inputs = set()
    results = []
    generator_state = None

  # Set up a measurement loop
  measurements = []
  tl = Timeloop()
  period = 30 # seconds
  @tl.job(interval=timedelta(seconds=period))
  def measure_progress():
    new_fuzz_inputs = set((output_path/'fuzz-inputs').glob('*')) - fuzz_inputs
    fuzz_inputs.update(new_fuzz_inputs)
    measurements.append({'exe_time': period,
                        'new_fuzz_inputs': new_fuzz_inputs,
                        })
    print(f'\nMeasurement recorded!\n')

  try:
    tl.start(block=False)
    generator_state = random_seed_generator.run(config)
  except Exception as e:
    print(f'Exception of type {type(e)} in random_search: {e}.')

  print(f'Measurement thread will stop in {period} seconds...')
  time.sleep(period)
  tl.stop()
  results.append({'measurements': measurements,
                  'generator_state': generator_state
                  })

  with open(results_file, 'w') as f:
    f.write(jsonpickle.encode(results))
