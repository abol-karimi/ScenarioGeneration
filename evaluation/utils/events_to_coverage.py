#!/usr/bin/env python3

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
import importlib

from scenic.domains.driving.roads import Network

from scenariogen.core.coverages.coverage import StatementSetCoverage
from evaluation.configs import coverage_config


def add_coverage(measurement, config):
  statement_coverages = []

  for path in measurement['new_event_files']:
    if not path.is_file():
      continue
    with open(path, 'r') as f:
      events = jsonpickle.decode(f.read())   
    if events:
      cov = config['coverage-module'].to_coverage(events, config)
      statement_coverages.append(cov)
  
  measurement['statement-set-coverage'] = StatementSetCoverage(statement_coverages)


def report(test_config):
  results_file_path = Path(test_config['results-file'])
  fuzz_inputs_path = Path(test_config['seeds-folder'])
  coverage_file_path = Path(test_config['output-folder'])/'coverage.json'
  test_coverage = test_config['coverage-config']['coverage-module']

  with open(tuple(fuzz_inputs_path.glob('*'))[0], 'r') as f:
    seed = jsonpickle.decode(f.read())
  
  config = {**seed.config,
            **coverage_config,
            'network': Network.fromFile(seed.config['map']),
            'coverage-module': importlib.import_module(f'scenariogen.core.coverages.{test_coverage}')
            }

  with open(results_file_path, 'r') as f:
    results = jsonpickle.decode(f.read())
 
  for result in results:
    for measurement in result['measurements']:
      add_coverage(measurement, config)

  with open(coverage_file_path, 'w') as f:
    f.write(jsonpickle.encode(results, indent=1))
