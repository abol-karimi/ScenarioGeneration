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
  gen_coverage = 'traffic'
  ego_coverage = f"{gen_ego if gen_ego else 'openLoop'}_{gen_coverage}"  

  config = {'scenario_path': f'experiments/seeds/random/definitions/4way-stop.scenic',
            'fuzz-inputs-folder': f'experiments/random_search/gen_{ego_coverage}/fuzz-inputs',
            'bugs-folder': f"experiments/Atheris/gen_{ego_coverage}/test_{ego_coverage}/bugs",
            **coverage_config,
            'coverage_module': gen_coverage,
            'events-folder': f'experiments/random_search/gen_{ego_coverage}/test_{ego_coverage}/events',
            'simulator': 'carla',
            'render_spectator': False,
            'render_ego': False,
            'PRNG_seed': 0,
            'spline_degree': 3,
            'spline_knots_size': 50,
            'scene_maxIterations': 50,
            'simulate_maxIterations': 1,
            'max-total-time': 7988, # seconds
            }

  results_file_path = Path(f'experiments/PCGF/gen_{ego_coverage}/results.json')  
  fuzz_inputs_path = Path(config['fuzz-inputs-folder'])
  events_path = Path(config['events-folder'])
  bugs_path = Path(config['bugs-folder'])

  # Decide to resume or start
  if results_file_path.is_file():
    print('Resume option not implemented yet!')
    exit(1)
  else:
    fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
    events_path.mkdir(parents=True, exist_ok=True)
    bugs_path.mkdir(parents=True, exist_ok=True)
    for path in fuzz_inputs_path.glob('*'):
      path.unlink()
    for path in events_path.glob('*'):
      path.unlink()
    for path in bugs_path.glob('*'):
      path.unlink()

    past_event_files = set()
    results = []
    generator_state = None

  # Set up a measurement loop
  measurements = [{'exe_time': 0,
                   'new_event_files': set(),
                  }]
  tl = Timeloop()
  period = 60 # seconds
  @tl.job(interval=timedelta(seconds=period))
  def measure_progress():
    new_event_files = set(events_path.glob('*')) - past_event_files
    past_event_files.update(new_event_files)
    measurements.append({'exe_time': period,
                        'new_event_files': new_event_files,
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

  with open(results_file_path, 'w') as f:
    f.write(jsonpickle.encode(results, indent=1))
