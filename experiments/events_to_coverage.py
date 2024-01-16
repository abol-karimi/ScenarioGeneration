#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import importlib

from scenic.domains.driving.roads import Network

from scenariogen.core.coverages.coverage import StatementSetCoverage


def add_coverage(measurement, config):
  measurement['statement-set-coverage'] = StatementSetCoverage([])

  for path in measurement['new_event_files']:
    if not path.is_file():
      continue
    print(path)
    with open(path, 'r') as f:
      events = jsonpickle.decode(f.read())
    
    if events:
      cov = config['coverage_module'].to_coverage(events, config)
      measurement['statement-set-coverage'].update(cov)


def report(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage):
  results_file_path = Path(f'experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/results.json')
  fuzz_inputs_path = Path(f'experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/fuzz-inputs')
  coverage_file_path = Path(f'experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/test_{test_ego}_{test_coverage}/coverage.json')

  with open(tuple(fuzz_inputs_path.glob('*'))[0], 'r') as f:
    seed = jsonpickle.decode(f.read())
  
  config = {**seed.config,
            'network': Network.fromFile(seed.config['map']),
            'coverage_module': importlib.import_module(f'scenariogen.core.coverages.{test_coverage}')
            }

  with open(results_file_path, 'r') as f:
    results = jsonpickle.decode(f.read())
 
  for result in results:
    for measurement in result['measurements']:
      add_coverage(measurement, config)

  with open(coverage_file_path, 'w') as f:
    f.write(jsonpickle.encode(results, indent=1))


if __name__ == '__main__':
  reports_config = (
    ('Atheris', 'TFPP', 'traffic', 'TFPP', 'traffic'),
    ('random_search', 'TFPP', 'traffic', 'TFPP', 'traffic'),
    # ('predicateFuzz', 'TFPP', 'traffic', 'TFPP', 'traffic'),
    # ('Atheris', 'TFPP', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'TFPP', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'autopilot', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'autopilot', 'traffic', 'TFPP', 'traffic'),
    # ('Atheris', 'autopilot', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'BehaviorAgent', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'BehaviorAgent', 'traffic', 'TFPP', 'traffic'),
    # ('Atheris', 'BehaviorAgent', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'intersectionAgent', 'traffic', 'intersectionAgent', 'traffic'),
    # ('Atheris', 'intersectionAgent', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'intersectionAgent', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'openLoop', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'openLoop', 'traffic', 'BehaviorAgent', 'traffic'),
  )

  for experiment_type, gen_ego, gen_coverage, test_ego, test_coverage in reports_config:
    print(f'Now running report: {experiment_type, gen_ego, gen_coverage, test_ego, test_coverage}')
    report(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage)