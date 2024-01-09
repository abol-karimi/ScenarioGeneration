#!/usr/bin/env python3.8

import jsonpickle
from pathlib import Path
from functools import reduce
from timeloop import Timeloop
from datetime import timedelta
import time

# This project
from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzzing.crossovers import StructureAwareCrossOver
from scenariogen.core.fuzzing.fuzzers.atheris import AtherisFuzzer
from experiments.configs import SUT_config, coverage_config

if __name__ == '__main__':

  fuzzing_ego = 'TFPP'
  coverage_module = 'traffic'

  fuzzer_config = {
    'SUT_config': {**SUT_config,
                  'ego_module': f'experiments.agents.{fuzzing_ego}' if fuzzing_ego else None,
                  'simulator': 'carla',
                  },
    'coverage_config': {**coverage_config,
                        'coverage_module': coverage_module
                        },
    'seeds_folder': f'experiments/seeds/random/seeds',
    'output_folder': f"experiments/Atheris/output_{fuzzing_ego if fuzzing_ego else 'openLoop'}_{coverage_module}",
    'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                    max_mutations_per_iteration=1,
                                    randomizer_seed=0),
    'crossOver': StructureAwareCrossOver(max_spline_knots_size=50,
                                        max_attempts=1,
                                        randomizer_seed=0),
    'atheris_runs': 4,
    'max_seed_length': 1e+6, # 1 MB
  }

  atheris_fuzzer = AtherisFuzzer(fuzzer_config)

  output_path = Path(fuzzer_config['output_folder'])
  fuzz_inputs_path = output_path/'fuzz-inputs'
  bugs_path = output_path/'bugs'
  coverages_path = output_path/f'coverages'

  # Decide to resume or start
  results_file = output_path/'results.json'
  if results_file.is_file():
    coverages = set((output_path/'coverages').glob('*'))
    with open(results_file, 'r') as f:
      results = jsonpickle.decode(f.read())
    merged_results = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements'],
                                            'atheris_state': r2['atheris_state']
                                          },
                            results)
    new_coverages = [m[1] for m in merged_results['measurements']]
    results_coverages = reduce(lambda i1,i2: i1.union(i2),
                            new_coverages)
    if results_coverages != coverages:
      print('Cannot resume Atheris: the fuzz-inputs in the folder do not match the fuzz-inputs of results.json.')
      exit(1)
    atheris_state = results[-1]['atheris_state']
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
    coverages = set()
    results = []
    atheris_state = None

  # Set up a measurement loop
  measurements = []
  tl = Timeloop()
  period = 30 # seconds
  @tl.job(interval=timedelta(seconds=period))
  def measure_progress():
    new_coverages = set((output_path/'coverages').glob('*')) - coverages
    coverages.update(new_coverages)
    measurements.append({'exe_time': period,
                        'new_coverages': new_coverages,
                        })
    print(f'\nMeasurement recorded!\n')

  try:
    tl.start(block=False)
    atheris_state = atheris_fuzzer.run(atheris_state=atheris_state)
  except Exception as e:
    print(f'Exception of type {type(e)} in atheris fuzzer: {e}.')

  print(f'Measurement thread will stop in {period} seconds...')
  time.sleep(period)
  tl.stop()
  results.append({'measurements': measurements,
                  'atheris_state': atheris_state
                  })

  with open(results_file, 'w') as f:
    f.write(jsonpickle.encode(results, indent=1))
