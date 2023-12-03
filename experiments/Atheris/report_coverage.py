#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce

from experiments.configs import SUT_config, coverage_config
from scenariogen.core.coverages.coverage import from_corpus, StatementCoverage

def report(fuzzing_ego, coverage_ego, coverage):
  output_folder = f"experiments/Atheris/output_{fuzzing_ego if fuzzing_ego else 'openLoop'}"
  output_path = Path(output_folder)
  results_file = output_path/'results_Atheris.json'

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
    for measurement in result['measurements']:
      coverages = tuple(input2statementCoverage[p] for p in measurement['new_fuzz_inputs'] if p in input2statementCoverage)
      measurement['statement_coverage'] = reduce(lambda c1,c2: c1+c2,
                                                  coverages,
                                                  StatementCoverage([]))

  with open(output_path/f"coverage_{coverage_ego}.json", 'w') as f:
    f.write(jsonpickle.encode(results))



if __name__ == '__main__':
  reports_config = (
    ('autopilot', 'autopilot', 'traffic_rules'),
    ('autopilot', 'BehaviorAgent', 'traffic_rules'),
    ('BehaviorAgent', 'autopilot', 'traffic_rules'),
    # ('BehaviorAgent', 'BehaviorAgent', 'traffic_rules'),
    (None, 'autopilot', 'traffic_rules'),
    (None, 'BehaviorAgent', 'traffic_rules'),
  )
  for fuzzing_ego, coverage_ego, coverage in reports_config:
    report(fuzzing_ego, coverage_ego, coverage)