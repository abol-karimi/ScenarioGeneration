#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import hashlib
import os
import jsonpickle
from functools import reduce

from experiments.configs import SUT_config, coverage_config
from scenariogen.core.coverages.coverage import StatementCoverage
from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError
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
  }

  for fuzz_input_path in paths:
    with open(fuzz_input_path, 'r') as f:
      fuzz_input = jsonpickle.decode(f.read())
    try:
      print(f'Evaluating fuzz-input {fuzz_input_path}')
      sim_result = Scenario(fuzz_input).run({'render_spectator': False,
                                             'render_ego': False,
                                             **config,
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
    # ('predicateFuzz', 'random', 'TFPP', 'traffic', 'TFPP', 'traffic'),
    # ('Atheris', 'random', 'TFPP', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'random', 'TFPP', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'random', 'autopilot', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'random', 'autopilot', 'traffic', 'TFPP', 'traffic'),
    # ('Atheris', 'random', 'autopilot', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'random', 'BehaviorAgent', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'random', 'BehaviorAgent', 'traffic', 'TFPP', 'traffic'),
    # ('Atheris', 'random', 'BehaviorAgent', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'random', 'intersectionAgent', 'traffic', 'intersectionAgent', 'traffic'),
    # ('Atheris', 'random', 'intersectionAgent', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'random', 'intersectionAgent', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'random', 'openLoop', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'random', 'openLoop', 'traffic', 'BehaviorAgent', 'traffic'),
  )

  for experiment_type, seeds, gen_ego, gen_coverage, test_ego, test_coverage in reports_config:
    print(f'Now running report: {experiment_type, seeds, gen_ego, gen_coverage, test_ego, test_coverage}')
    report(experiment_type, seeds, gen_ego, gen_coverage, test_ego, test_coverage)