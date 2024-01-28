#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt
import importlib
from collections import Counter
import numpy as np


def plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage, ax, plot_label):
  global predicates
  global multiplier
  global width
  global x

  coverage_file_path = Path(f'experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/test_{test_ego}_{test_coverage}/coverage.json')

  with open(coverage_file_path, 'r') as f:
    coverage = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                          coverage)['measurements']
  event_files = reduce(lambda m1, m2: {'new_event_files': m1['new_event_files'].union(m2['new_event_files'])},
                            measurements)['new_event_files']
  pred2count = Counter(statement.predicate for m in measurements
                                           for statement_cov in m['statement-set-coverage'].items
                                           for statement in statement_cov.items)
  # Normalize by the number of fuzz inputs
  for pred, count in pred2count.items():
    pred2count[pred] = count / len(event_files)

  if predicates is None:
    predicates = sorted(predicate_coverage_space.items, reverse=True, key=lambda p: pred2count[p])
    x = np.arange(len(predicates))*2  # the label locations
    ax.set_xticks(x+width, [str(p) for p in predicates])

  offset = width * multiplier
  ax.bar(x + offset,
          tuple(pred2count[p] for p in predicates),
          width,
          label=plot_label)


if __name__ == '__main__':
  
  # the x-axis domain is the predicate coverage space
  fuzz_inputs_path = Path(f'experiments/PCGF/gen_TFPP_traffic-rules/fuzz-inputs')
  with open(tuple(fuzz_inputs_path.glob('*'))[0], 'r') as f:
    seed = jsonpickle.decode(f.read())
  coverage_module = importlib.import_module(f'scenariogen.core.coverages.traffic-rules')
  predicate_coverage_space = coverage_module.coverage_space(seed.config)
  predicates = None

  fig_coverage = plt.figure(layout='constrained', figsize=(10, 6))
  # fig_coverage.suptitle(f'Baseline vs. Coverage-Guided Fuzzing')

  ax = fig_coverage.add_subplot(111)
  ax.set_xlabel('Predicate')
  ax.set_ylabel('Average Frequency (per fuzz-input)')
  ax.set_yscale('log')

  reports_config = (
    ('PCGF', 'TFPP', 'traffic-rules', 'TFPP', 'traffic-rules', ax, 'PCGF'),
    ('random_search', 'TFPP', 'traffic-rules', 'TFPP', 'traffic-rules', ax, 'Random search'),
    ('Atheris', 'TFPP', 'traffic-rules', 'TFPP', 'traffic-rules', ax, 'Atheris'),
  )

  width = 0.3
  multiplier = 0
  for experiment_type, gen_ego, gen_coverage, test_ego, test_coverage, plot_axes, plot_label in reports_config:
    print(f'Now plotting report: {experiment_type, gen_ego, gen_coverage, test_ego, test_coverage}')
    plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage, plot_axes, plot_label)
    multiplier += 1
  
  ax.legend(loc='upper right', ncols=3)
  plt.setp(ax.get_xticklabels(), rotation=45, ha='right')

  fig_coverage.savefig(f'experiments/ISSTA_plots/baseline-vs-PCGF_{test_coverage}_predicate-distribution.png')