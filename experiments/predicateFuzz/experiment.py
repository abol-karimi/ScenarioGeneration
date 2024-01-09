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

  fuzzing_ego = 'autopilot'
  simulator = 'carla'

  fuzzer_config = {
    'SUT_config': {**SUT_config,
                  'ego_module': f'experiments.agents.{fuzzing_ego}' if fuzzing_ego else None,
                  'simulator': simulator,
                  },
    'coverage_config': {**coverage_config,
                        'coverage_module': 'traffic'
                        },
    'seeds_folder': f'experiments/seeds/random/seeds/single',
    'output_folder': f"experiments/predicateFuzz/output_{fuzzing_ego if fuzzing_ego else 'openLoop'}",
    'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                    max_mutations_per_iteration=1,
                                    randomizer_seed=0),
    'crossOver': StructureAwareCrossOver(max_spline_knots_size=50,
                                        max_attempts=1,
                                        randomizer_seed=0),
    'schedule': PowerSchedule(),
    'max_total_time': 2*60, # seconds
    'max_seed_length': 1e+6, # 1 MB
  }

  fuzzer = ModularFuzzer(fuzzer_config)

  output_path = Path(fuzzer_config['output_folder'])
  fuzz_inputs_path = output_path/'fuzz-inputs'
  bugs_path = output_path/'bugs'
  coverages_path = output_path/'coverages'

  # Decide to resume or start
  results_file = output_path/'results.json'
  if results_file.is_file():
    fuzz_inputs = set((output_path/'fuzz-inputs').glob('*'))
    with open(results_file, 'r') as f:
      results = jsonpickle.decode(f.read())
    merged_results = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements'],
                                            'fuzzer_state': r2['fuzzer_state']
                                          },
                            results)
    new_fuzz_inputs = [m[1] for m in merged_results['measurements']]
    results_fuzz_inputs = reduce(lambda i1,i2: i1.union(i2),
                            new_fuzz_inputs)
    if results_fuzz_inputs != fuzz_inputs:
      print('Cannot resume fuzzer: the fuzz-inputs in the folder do not match the fuzz-inputs of results.json.')
      exit(1)
    fuzzer_state = results[-1]['fuzzer_state']
  else:
    fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
    bugs_path.mkdir(parents=True, exist_ok=True)
    coverages_path.mkdir(parents=True, exist_ok=True)
    for path in fuzz_inputs_path.glob('*'):
      path.unlink()
    for path in bugs_path.glob('*'):
      path.unlink()
    for path in coverages_path.glob('*'):
      path.unlink()
    fuzz_inputs = set()
    results = []
    fuzzer_state = None

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

  with open(results_file, 'w') as f:
    f.write(jsonpickle.encode(results, indent=1))






