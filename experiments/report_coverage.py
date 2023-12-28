#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import sys
import jsonpickle
from functools import reduce

from experiments.configs import SUT_config, coverage_config
from scenariogen.core.coverages.coverage import from_corpus, StatementCoverage
from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError
from scenic.core.simulators import SimulationCreationError

def process_measurment(measurement, config):
  output = {}
  output['nonego_collisions'] = set()
  output['ego_collisions'] = set()
  output['simulation_creation_errors'] = set()
  output['simulation_rejections'] = set()
  output['none_coverages'] = set()
  output['valid_inputs'] = set()
  output['statement_coverage'] = StatementCoverage([])

  for path in measurement['new_fuzz_inputs']:
    if not path.is_file():
      continue
    with open(path, 'r') as f:
      fuzz_input = jsonpickle.decode(f.read())
    try:
      print(f'Running {path.name}')
      sim_result = Scenario(fuzz_input).run({'render_spectator': False,
                                             'render_ego': False,
                                             **config,
                                             }
                                            )
    except NonegoCollisionError as err:
      output['nonego_collisions'].add(path)
      print(f'Collision between {err.nonego} and {err.other}.')
    except EgoCollisionError as err:
      output['ego_collisions'].add(path)
      print(f'Ego collided with {err.other}.')
    except SimulationCreationError as e:
      output['simulation_creation_errors'].add(path)
      print(e)
    except Exception as e:
      print(e)
    else:
      if not sim_result:
        print(f'Simulation rejected!')
        output['simulation_rejections'].add(path)
      elif sim_result.records['coverage'] is None:
        print(f'Simulation failed to report coverage!')
        output['none_coverages'].add(path)
      else:
        output['statement_coverage'].update(sim_result.records['coverage'])
    
  return output


def report(experiment_type, seeds, experiment, coverage_ego, coverage):
  output_path = Path(f'experiments/{experiment_type}/output_{experiment}')
  results_file = output_path/'results.json'

  config = {
    **SUT_config,
    **coverage_config,
    'ego_module': f'experiments.agents.{coverage_ego}',
    'coverage_module': f'scenariogen.core.coverages.{coverage}',
  }

  coverage_path = output_path/f'coverage_{coverage_ego}_{coverage}.json'
  if coverage_path.is_file():
    # Resume
    with open(coverage_path, 'r') as f:
      results = jsonpickle.decode(f.read())
  else:
    # Start
    with open(results_file, 'r') as f:
      results = jsonpickle.decode(f.read())

    results[0]['measurements'].insert(0,
                                      {'exe_time': 0,
                                       'new_fuzz_inputs': Path(f'experiments/seeds/{seeds}/seeds').glob('*') if seeds else set(),
                                      })
  
  for result in results:
    for measurement in result['measurements']:
      if not 'statement_coverage' in measurement:
        try:
          output = process_measurment(measurement, config)
        except KeyboardInterrupt:
          with open(coverage_path, 'w') as f:
            f.write(jsonpickle.encode(results))
            sys.exit(1)
        else:
          measurement.update(output)
  
  with open(coverage_path, 'w') as f:
    f.write(jsonpickle.encode(results))

if __name__ == '__main__':
  reports_config = (
    ('Atheris', 'random', 'autopilot', 'autopilot', 'traffic_rules'),
    ('Atheris', 'random', 'autopilot', 'BehaviorAgent', 'traffic_rules'),
    ('Atheris', 'random', 'BehaviorAgent', 'autopilot', 'traffic_rules'),
    ('Atheris', 'random', 'BehaviorAgent', 'BehaviorAgent', 'traffic_rules'),
    ('Atheris', 'random', 'intersectionAgent', 'autopilot', 'traffic_rules'),
    ('Atheris', 'random', 'intersectionAgent', 'BehaviorAgent', 'traffic_rules'),
    ('Atheris', 'random', 'openLoop', 'autopilot', 'traffic_rules'),
    ('Atheris', 'random', 'openLoop', 'BehaviorAgent', 'traffic_rules'),
    # ('random_search', None, 'autopilot', 'autopilot', 'traffic_rules'),
    # ('random_search', None, 'autopilot', 'BehaviorAgent', 'traffic_rules'),
    ('Atheris', 'random', 'autopilot', 'autopilot', 'traffic'),
    ('Atheris', 'random', 'autopilot', 'BehaviorAgent', 'traffic'),
    ('Atheris', 'random', 'BehaviorAgent', 'autopilot', 'traffic'),
    ('Atheris', 'random', 'BehaviorAgent', 'BehaviorAgent', 'traffic'),
    ('Atheris', 'random', 'intersectionAgent', 'autopilot', 'traffic'),
    ('Atheris', 'random', 'intersectionAgent', 'BehaviorAgent', 'traffic'),
    ('Atheris', 'random', 'openLoop', 'autopilot', 'traffic'),
    ('Atheris', 'random', 'openLoop', 'BehaviorAgent', 'traffic'),
    # ('random_search', None, 'autopilot', 'autopilot', 'traffic'),
    # ('random_search', None, 'autopilot', 'BehaviorAgent', 'traffic'),
  )

  for experiment_type, seeds, experiment, coverage_ego, coverage in reports_config:
    print(f'Now running report: {experiment_type, seeds, experiment, coverage_ego, coverage}')
    report(experiment_type, seeds, experiment, coverage_ego, coverage)