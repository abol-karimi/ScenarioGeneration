#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import importlib

from scenic.domains.driving.roads import Network

from scenariogen.core.coverages.coverage import StatementSetCoverage
from experiments.PCGF.experiment import get_config as PCGF_get_config
from experiments.Atheris.experiment import get_config as Atheris_get_config
from experiments.test import get_test_config


def add_coverage(measurement, config):
  statement_coverages = []

  for path in measurement['new_event_files']:
    if not path.is_file():
      continue
    with open(path, 'r') as f:
      events = jsonpickle.decode(f.read())   
    if events:
      cov = config['coverage_module'].to_coverage(events, config)
      statement_coverages.append(cov)
  
  measurement['statement-set-coverage'] = StatementSetCoverage(statement_coverages)


def report(test_config):
  results_file_path = Path(test_config['results-file'])
  fuzz_inputs_path = Path(test_config['seeds-folder'])
  coverage_file_path = Path(test_config['output-folder'])/'coverage.json'
  test_coverage = test_config['coverage-config']['coverage_module']

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
    ('PCGF', 'TFPP', 0, 4*60*60, 'traffic-rules', 'TFPP', 'traffic-rules'),
  )

  for experiment_type, gen_ego, randomizer_seed, max_total_time, gen_coverage, test_ego, test_coverage in reports_config:
    print(f'Now running report: {experiment_type, gen_ego, gen_coverage, test_ego, test_coverage}')
    output_folder = f'experiments/{experiment_type}/{gen_ego}_{gen_coverage}_{randomizer_seed}_{max_total_time}'
    if experiment_type == 'PCGF':
      gen_config = PCGF_get_config(gen_ego, gen_coverage, randomizer_seed, max_total_time, output_folder)
    elif experiment_type == 'Atheris':
      gen_config = Atheris_get_config(gen_ego, gen_coverage, randomizer_seed, max_total_time, output_folder)

    test_config = get_test_config(gen_config, test_ego, test_coverage, max_total_time)
    report(test_coverage)