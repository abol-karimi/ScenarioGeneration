#!/usr/bin/env python3.8
"""
Research question:
  Does prioritizing seeds based on their predicate-coverage improve the fuzzing performance?
"""


import jsonpickle
from pathlib import Path
from functools import reduce
from timeloop import Timeloop
from datetime import timedelta
import time

# This project
from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzzing.crossovers import StructureAwareCrossOver
from scenariogen.core.fuzzing.schedules import PowerSchedule
from scenariogen.core.fuzzing.fuzzers.modular import ModularFuzzer
from scenariogen.core.coverages.coverage import PredicateSetCoverage
from experiments.configs import SUT_config, coverage_config


if __name__ == '__main__':

  gen_ego = 'TFPP'
  gen_coverage = 'traffic'
  ego_coverage = f"{gen_ego if gen_ego else 'openLoop'}_{gen_coverage}"

  fuzzer_config = {
    'SUT-config': {**SUT_config,
                  'ego-module': f'experiments.agents.{gen_ego}' if gen_ego else None,
                  'simulator': 'carla',
                  },
    'coverage-config': {**coverage_config,
                        'coverage_module': gen_coverage
                        },
    'seeds-folder': f'experiments/seeds/random/seeds',
    'fuzz-inputs-folder': f"experiments/PCGF/gen_{ego_coverage}/fuzz-inputs",
    'events-folder': f"experiments/PCGF/gen_{ego_coverage}/test_{ego_coverage}/events",
    'bugs-folder': f"experiments/PCGF/gen_{ego_coverage}/test_{ego_coverage}/bugs",
    'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                    max_mutations_per_iteration=1,
                                    randomizer_seed=0),
    'crossOver': StructureAwareCrossOver(max_spline_knots_size=50,
                                        max_attempts=1,
                                        randomizer_seed=0),
    'schedule': PowerSchedule(),
    'max-total-time': 274, # seconds
    'max_seed_length': 1e+6, # 1 MB
  }

  fuzzer = ModularFuzzer(fuzzer_config)

  results_file_path = Path(f'experiments/PCGF/gen_{ego_coverage}/results.json')
  fuzz_inputs_path = Path(fuzzer_config['fuzz-inputs-folder'])
  events_path = Path(fuzzer_config['events-folder'])
  bugs_path = Path(fuzzer_config['bugs-folder'])

  # Decide to resume or start
  if results_file_path.is_file():
    # resume
    event_files = set((events_path).glob('*'))
    with open(results_file_path, 'r') as f:
      results = jsonpickle.decode(f.read())
    merged_results = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements'],
                                            'atheris_state': r2['atheris_state']
                                          },
                            results)
    results_event_files = reduce(lambda i1,i2: i1.union(i2),
                            [m['new_event_files'] for m in merged_results['measurements']])
    if results_event_files != event_files:
      print('Cannot resume PCGF: the event_files in the folder do not match the event_files of results.json.')
      exit(1)
    fuzzer_state = results[-1]['fuzzer_state']
  else:
    # start
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
    fuzzer_state = None

  # Set up a measurement loop
  measurements = []
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
  fuzzer_state = fuzzer.run(fuzzer_state=fuzzer_state)
  # except Exception as e:
  #   print(f'Exception of type {type(e)} in modular fuzzer: {e}.')

  print(f'Measurement thread will stop in {period} seconds...')
  time.sleep(period)
  tl.stop()
  results.append({'measurements': measurements,
                  'fuzzer_state': fuzzer_state
                  })

  with open(results_file_path, 'w') as f:
    f.write(jsonpickle.encode(results, indent=1))






