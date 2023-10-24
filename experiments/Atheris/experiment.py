#!/usr/bin/env python3.8

import jsonpickle
import time
from pathlib import Path
import carla

# This project
from scenariogen.core.mutators import StructureAwareMutator
from scenariogen.core.crossovers import StructureAwareCrossOver
from scenariogen.core.fuzzers.atheris import AtherisFuzzer

SUT_config = {
  'render_spectator': False,
  'render_ego': False,
  'weather': 'CloudySunset',
  'arrival_distance': 4,
  'stopping_speed': 0.5,
  'moving_speed': 0.6,
  'closedLoop': True,
  'ego_module': 'experiments.agents.autopilot_route',
  'simulator': 'carla',
  'coverage_module': None,
}

fuzzer_config = {
  'SUT_config': SUT_config,
  'seeds_folder': f'experiments/seeds_manual',
  'output_folder': f'experiments/Atheris/output',
  'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                   max_mutations_per_iteration=1,
                                   randomizer_seed=0),
  'crossOver': StructureAwareCrossOver(max_spline_knots_size=50,
                                       max_attempts=1,
                                       randomizer_seed=0),
  'atheris_runs': 50,
  'max_seed_length': 1e+6, # 1 MB
}

atheris_fuzzer = AtherisFuzzer(fuzzer_config)

output_path = Path(fuzzer_config['output_folder'])
report_file = output_path/'report.json'
if report_file.is_file():
  with open(report_file, 'r') as f:
    report = jsonpickle.decode(f.read())
    atheris_state = report[-1][1]
    fuzz_inputs = set((output_path/'fuzz-inputs').glob('*'))
else:
  report = []
  atheris_state = None
  fuzz_inputs = set()

for i in range(10):
  try:
    start = time.time()
    atheris_state = atheris_fuzzer.run(atheris_state=atheris_state)
    exe_time = time.time() - start
  except Exception as e:
    print(f'Exception of type {type(e)} in atheris fuzzer: {e}.')
    break

  client = carla.Client('127.0.0.1', 2000)
  client.reload_world()

  new_fuzz_inputs = set((output_path/'fuzz-inputs').glob('*')) - fuzz_inputs
  fuzz_inputs.update(new_fuzz_inputs)

  report.append((exe_time, atheris_state, new_fuzz_inputs))

  with open(f"{fuzzer_config['output_folder']}/report.json", 'w') as f:
    f.write(jsonpickle.encode(report))





