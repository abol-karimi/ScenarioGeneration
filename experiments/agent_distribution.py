#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
import matplotlib.pyplot as plt
from collections import Counter

from scenariogen.predicates.events import ActorSpawnedEvent


def plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage):
  output_path = Path(f"experiments/{experiment_type}/output_{gen_ego}_{gen_coverage}")

  nonegos_num = []
  for path in (output_path/'events').glob('*'):
    with open(path, 'r') as f:
      events = jsonpickle.decode(f.read())
    if not events:
      continue
    nonegos = {e.vehicle for e in events if type(e) is ActorSpawnedEvent and e.vehicle != 'ego'}
    nonegos_num.append(len(nonegos))
  
  nonegos_num.sort()
  distribution = Counter(nonegos_num)
  
  fig = plt.figure()
  fig.suptitle(f'Experiment type: {experiment_type},\n Generation ego: {gen_ego},\n Test ego: {test_ego}')

  ax = fig.add_subplot(111)    # The big subplot
  ax.set_xlabel('Number of agents')
  ax.set_ylabel('Frequency')
  ax.plot(tuple(distribution.keys()), tuple(distribution.values()), 'bo')

  plt.tight_layout()
  plt.savefig(output_path/f'nonegos_num_distribution_{test_ego}_{test_coverage}.png')

if __name__ == '__main__':
  reports_config = (
    ('Atheris', 'TFPP', 'traffic', 'TFPP', 'traffic'),
    ('random_search', 'TFPP', 'traffic', 'TFPP', 'traffic'),
    # ('predicateFuzz', 'TFPP', 'traffic', 'TFPP', 'traffic'),
    # ('Atheris', 'autopilot', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'autopilot', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'BehaviorAgent', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'BehaviorAgent', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'intersectionAgent', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'intersectionAgent', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'openLoop', 'traffic', 'autopilot', 'traffic'),
    # ('Atheris', 'openLoop', 'traffic', 'BehaviorAgent', 'traffic'),
    # ('random_search', 'autopilot', 'traffic', 'autopilot', 'traffic'),
    # ('random_search', '4way-stop_autopilot', 'traffic', 'BehaviorAgent', 'traffic'),
  )

  for experiment_type, gen_ego, gen_coverage, test_ego, test_coverage in reports_config:
    plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage)