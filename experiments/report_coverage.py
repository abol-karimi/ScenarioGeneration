#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
from tqdm import tqdm

from experiments.configs import SUT_config, coverage_config
from scenariogen.core.coverages.coverage import from_corpus, StatementCoverage

def report(experiment_type, experiment_name, coverage_ego, coverage):
  output_folder = f"experiments/{experiment_type}/output_{experiment_name}"
  output_path = Path(output_folder)
  results_file = output_path/'results.json'

  config = {
    **SUT_config,
    **coverage_config,
    'ego_module': f'experiments.agents.{coverage_ego}',
    'coverage_module': f'scenariogen.core.coverages.{coverage}',
  }

  seed2statementCoverage = from_corpus('experiments/seeds_4way-stop_random', config)
  fuzzInput2statementCoverage = from_corpus(output_path/'fuzz-inputs', config)
  input2statementCoverage = {**seed2statementCoverage, **fuzzInput2statementCoverage}

  with open(results_file, 'r') as f:
    results = jsonpickle.decode(f.read())
  results[0]['measurements'].insert(0, {'exe_time': 0,
                                        'new_fuzz_inputs': Path('experiments/seeds_4way-stop_random').glob('*'),
                                        })

  for result in results:
    for measurement in tqdm(result['measurements']):
      coverages = tuple(input2statementCoverage[p] for p in measurement['new_fuzz_inputs'] if p in input2statementCoverage)
      measurement['statement_coverage'] = reduce(lambda c1,c2: c1+c2,
                                                  coverages,
                                                  StatementCoverage([]))

  with open(output_path/f"coverage_{coverage_ego}.json", 'w') as f:
    f.write(jsonpickle.encode(results))



if __name__ == '__main__':
  reports_config = (
    # ('Atheris', 'autopilot', 'autopilot', 'traffic_rules'),
    # ('Atheris', 'autopilot', 'BehaviorAgent', 'traffic_rules'),
    ('Atheris', 'autopilot', 'BehaviorAgentRSS', 'traffic_rules'),
    # ('Atheris', 'BehaviorAgent', 'autopilot', 'traffic_rules'),
    # ('Atheris', 'BehaviorAgent', 'BehaviorAgent', 'traffic_rules'),
    ('Atheris', 'BehaviorAgent', 'BehaviorAgentRSS', 'traffic_rules'),
    # ('Atheris', 'intersectionAgent', 'autopilot', 'traffic_rules'),
    # ('Atheris', 'intersectionAgent', 'BehaviorAgent', 'traffic_rules'),
    # ('Atheris', 'openLoop', 'autopilot', 'traffic_rules'),
    # ('Atheris', 'openLoop', 'BehaviorAgent', 'traffic_rules'),
    ('Atheris', 'openLoop', 'BehaviorAgentRSS', 'traffic_rules'),
    # ('random_search', '4way-stop_random', 'autopilot', 'traffic_rules'),
    # ('random_search', '4way-stop_random', 'BehaviorAgent', 'traffic_rules'),
  )

  for experiment_type, experiment_name, coverage_ego, coverage in reports_config:
    report(experiment_type, experiment_name, coverage_ego, coverage)