#!/usr/bin/env python3

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
import matplotlib.pyplot as plt
from collections import Counter

from scenariogen.predicates.events import AgentSpawnedEvent


def plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage):
  events_path = Path(f"experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/test_{test_ego}_{test_coverage}/events")
  fig_path = Path(f"experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/test_{test_ego}_{test_coverage}/nonegos_num_distribution.png")

  nonegos_num = []
  for path in events_path.glob('*'):
    with open(path, 'r') as f:
      events = jsonpickle.decode(f.read())
    if not events:
      continue
    nonegos = {e.vehicle for e in events if type(e) is AgentSpawnedEvent and e.vehicle != 'ego'}
    nonegos_num.append(len(nonegos))
  
  nonegos_num.sort()
  distribution = Counter(nonegos_num)
  print(distribution)
  
  fig = plt.figure()
  fig.suptitle(f'Experiment type: {experiment_type},\n Generation ego: {gen_ego},\n Test ego: {test_ego}')

  ax = fig.add_subplot(111)    # The big subplot
  ax.set_xlabel('Number of agents')
  ax.set_ylabel('Frequency')
  ax.plot(tuple(distribution.keys()), tuple(distribution.values()), 'bo')

  plt.tight_layout()
  fig.savefig(fig_path)

if __name__ == '__main__':
  reports_config = (
    ('Atheris', 'TFPP', 'traffic', 'TFPP', 'traffic'),
    # ('random_search', 'TFPP', 'traffic', 'TFPP', 'traffic'),
  )

  for experiment_type, gen_ego, gen_coverage, test_ego, test_coverage in reports_config:
    plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage)