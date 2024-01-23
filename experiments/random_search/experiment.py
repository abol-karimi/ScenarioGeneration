#!/usr/bin/env python3.8

"""
Research question:
  Can we beat random search as a baseline?

"""

import jsonpickle
from pathlib import Path
from timeloop import Timeloop
from datetime import timedelta
import time

from scenariogen.core.seed_generators import random as random_seed_generator
from experiments.configs import coverage_config
from experiments.runner import run


def run(config):
  results_file_path = Path(config['results-file'])
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
                   'elapsed_time': 0,                   
                   'new_event_files': set(),
                  }]
  tl = Timeloop()
  period = 120 # seconds
  @tl.job(interval=timedelta(seconds=period))
  def measure_progress():
    new_event_files = set(events_path.glob('*')) - past_event_files
    past_event_files.update(new_event_files)
    measurements.append({'exe_time': period,
                         'elapsed_time': time.time()-start_time,
                         'new_event_files': new_event_files,
                        })
    partial_result = [{'measurements': measurements,
                      'generator-state': None
                      }]
    with open(results_file_path, 'w') as f:
      f.write(jsonpickle.encode(results+partial_result, indent=1))

    print(f'\nMeasurement recorded!\n')

  tl.start(block=False)
  start_time = time.time()
  try:
    generator_state = random_seed_generator.run(config)
  except Exception as e:
    print(f'Exception of type {type(e)} in atheris fuzzer: {e}.')
    raise e
  finally:
    tl.stop()
    print(f'Measurement thread stopped.')

  # Measure one last time in case the the time-loop thread missed some new results
  measure_progress()
  
  results.append({'measurements': measurements,
                  'generator-state': generator_state
                  })

  with open(results_file_path, 'w') as f:
    f.write(jsonpickle.encode(results, indent=1))


if __name__ == '__main__':
  gen_ego = 'TFPP'
  gen_coverage = 'traffic'

  config = {
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
    'PRNG-seed': 0,
    'spline-degree': 3,
    'spline-knots-size': 50,
    'scene-maxIterations': 50,
    'simulate-maxIterations': 1,
    'max-total-time': 4*60*60, # seconds
    }
  
  run(config)
