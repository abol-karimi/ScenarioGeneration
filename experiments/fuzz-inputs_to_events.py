#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import hashlib
import os
import jsonpickle
from functools import reduce

from experiments.configs import SUT_config, coverage_config
from scenariogen.core.fuzzing.runner import Runner
from scenic.core.simulators import SimulationCreationError


def report(experiment_type, seeds, gen_ego, gen_coverage, test_ego, test_coverage):
  events_path = Path(f"experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/test_{test_ego}_{test_coverage}/events")
  fuzz_inputs_path = Path(f'experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/fuzz-inputs')
  paths = list(fuzz_inputs_path.glob('*'))
  if seeds:
    paths.extend(Path(f'experiments/seeds/{seeds}/seeds').glob('*'))
  
  event_files = set(p.name for p in events_path.glob('*'))
  paths = list(filter(lambda p: not p.name in event_files, paths))
  paths.sort(key=lambda x: os.path.getmtime(x))

  config = {
    **SUT_config,
    **coverage_config,
    'ego-module': f'experiments.agents.{test_ego}',
    'coverage_module': test_coverage,
    'render-spectator': False,
    'render-ego': False,
  }

  for fuzz_input_path in paths:
    with open(fuzz_input_path, 'r') as f:
      fuzz_input = jsonpickle.decode(f.read())
    try:
      print(f'Evaluating fuzz-input {fuzz_input_path}')
      sim_result = Runner.run({**config,
                               **fuzz_input.config,                               
                               'fuzz-input': fuzz_input,
                              }
                             )
    except KeyboardInterrupt:
      exit(1)
    except SimulationCreationError as e:
      print(f'Exception in SUTCallback: {e}')
    else:
      if sim_result and 'events' in sim_result.records and sim_result.records['events']:
        # Save coverage events to disk
        with open(events_path/fuzz_input_path.name, 'w') as f:
          f.write(jsonpickle.encode(sim_result.records['events'], indent=1))


if __name__ == '__main__':
  reports_config = (
    # ('Atheris', 'random', 'TFPP', 'traffic', 'TFPP', 'traffic'),
    ('random_search', None, 'TFPP', 'traffic', 'TFPP', 'traffic'),
  )

  for experiment_type, seeds, gen_ego, gen_coverage, test_ego, test_coverage in reports_config:
    print(f'Now running report: {experiment_type, seeds, gen_ego, gen_coverage, test_ego, test_coverage}')
    report(experiment_type, seeds, gen_ego, gen_coverage, test_ego, test_coverage)