#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt
import importlib
from collections import Counter

from scenariogen.core.coverages.coverage import StatementCoverage, PredicateSetCoverage, PredicateCoverage


def plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage, ax, plot_label, plot_color):
  global predicates
  coverage_file_path = Path(f'experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/test_{test_ego}_{test_coverage}/coverage.json')

  with open(coverage_file_path, 'r') as f:
    coverage = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                          coverage)['measurements']
  pred2count = Counter(statement.predicate for m in measurements
                                           for statement_cov in m['statement-set-coverage'].items
                                           for statement in statement_cov.items)
  if predicates is None:
    predicates = sorted(predicate_coverage_space.items, reverse=True, key=lambda p: pred2count[p])

  ax.bar(tuple(p.name for p in predicates),
         tuple(pred2count[p] for p in predicates),
         width=0.3,
         align='center')
  
  ax.set_ylabel(plot_label)
  ax.set_yscale('log')


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
  # Turn off axis lines and ticks of the big subplot
  ax.spines['top'].set_color('none')
  ax.spines['bottom'].set_color('none')
  ax.spines['left'].set_color('none')
  ax.spines['right'].set_color('none')
  ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)

  ax1 = fig_coverage.add_subplot(311)
  ax2 = fig_coverage.add_subplot(312)
  ax3 = fig_coverage.add_subplot(313)

  ax1.tick_params(top=False, bottom=False, right=False)
  ax2.tick_params(top=False, bottom=False, right=False)

  ax1.set_xticklabels([])
  ax2.set_xticklabels([])

  ax3.set_xlabel('Predicate')

  reports_config = (
    ('PCGF', 'TFPP', 'traffic-rules', 'TFPP', 'traffic-rules', ax1, 'PCGF', 'm'),
    ('random_search', 'TFPP', 'traffic', 'TFPP', 'traffic-rules', ax2, 'Random search', 'b'),
    ('Atheris', 'TFPP', 'traffic-rules', 'TFPP', 'traffic-rules', ax3, 'Atheris', 'k'),
  )

  for experiment_type, gen_ego, gen_coverage, test_ego, test_coverage, plot_axes, plot_label, plot_color in reports_config:
    print(f'Now plotting report: {experiment_type, gen_ego, gen_coverage, test_ego, test_coverage}')
    plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage, plot_axes, plot_label, plot_color)
  
  plt.setp(ax3.get_xticklabels(), rotation=45, ha='right')

  plt.savefig(f'experiments/ISSTA_plots/baseline-vs-PCGF_{test_coverage}_predicate-distribution.png')