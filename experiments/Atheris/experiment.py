#!/usr/bin/env python3.8

import jsonpickle
import time
from pathlib import Path

# This project
from scenariogen.core.mutators import StructureAwareMutator
from scenariogen.core.crossovers import StructureAwareCrossOver
from scenariogen.core.fuzzers.atheris import AtherisFuzzer

SUT_config = {
  'render_spectator': True,
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
  'atheris_runs': 5,
  'max_seed_length': 1e+6, # 1 MB
}

atheris_fuzzer = AtherisFuzzer(fuzzer_config)

report_file = Path(fuzzer_config['output_folder'])/'report.json'
if report_file.is_file():
  with open(report_file, 'r') as f:
    report = jsonpickle.decode(f.read())
    atheris_state = report[-1][1]
else:
  report = []
  atheris_state = None

for i in range(2):
  start = time.time()
  atheris_state = atheris_fuzzer.run(atheris_state=atheris_state)
  exe_time = time.time() - start
  
  report.append((exe_time, atheris_state))

  with open(f"{fuzzer_config['output_folder']}/report.json", 'w') as f:
    f.write(jsonpickle.encode(report))





