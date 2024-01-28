#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt

from scenariogen.core.coverages.coverage import Predicate, StatementCoverage, PredicateSetCoverage, PredicateCoverage


def plot_curve(gen_config, test_config, plot_color, plot_label, axes):
  coverage_file_path = Path(test_config['output-folder'])/'coverage.json'

  with open(coverage_file_path, 'r') as f:
    coverage = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                          coverage)['measurements']
  elapsed_times = tuple(int(m['elapsed_time']/60) for m in measurements)
  ego_violation_filter = lambda s: s.predicate in {Predicate(name) for name in {'violatesRule',
                                                                                'violatesRightOfForRule',
                                                                                'collidedWithAtTime'}} \
                                    and s.args[0] == 'ego'
  statementSet_coverages = tuple(m['statement-set-coverage'].filter(ego_violation_filter) for m in measurements)

  statementSet_coverages_acc = [statementSet_coverages[0]]
  for i in range(1, len(measurements)):
    statementSet_coverages_acc.append(statementSet_coverages_acc[-1] + statementSet_coverages[i])
  
  statement_coverages_acc = tuple(c.cast_to(StatementCoverage) for c in statementSet_coverages_acc)
  predicateSet_coverages_acc = tuple(c.cast_to(PredicateSetCoverage) for c in statementSet_coverages_acc)
  predicate_coverages_acc = tuple(c.cast_to(PredicateCoverage) for c in statement_coverages_acc)

  ax1, ax2, ax3, ax4 = axes
  ax1.plot(elapsed_times, tuple(len(c) for c in statementSet_coverages_acc), f'{plot_color}-', label=plot_label)
  ax2.plot(elapsed_times, tuple(len(c) for c in statement_coverages_acc), f'{plot_color}-', label=plot_label)
  ax3.plot(elapsed_times, tuple(len(c) for c in predicateSet_coverages_acc), f'{plot_color}-', label=plot_label)
  ax4.plot(elapsed_times, tuple(len(c) for c in predicate_coverages_acc), f'{plot_color}-', label=plot_label)


def plot(plot_configs):
  fig_coverage = plt.figure(layout='constrained')
  # fig_coverage.suptitle(f'Baseline vs. Coverage-Guided Fuzzing')

  ax = fig_coverage.add_subplot(111)    # The big subplot
  # Turn off axis lines and ticks of the big subplot
  ax.spines['top'].set_color('none')
  ax.spines['bottom'].set_color('none')
  ax.spines['left'].set_color('none')
  ax.spines['right'].set_color('none')
  ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)

  ax1 = fig_coverage.add_subplot(411)
  ax2 = fig_coverage.add_subplot(412)
  ax3 = fig_coverage.add_subplot(413)
  ax4 = fig_coverage.add_subplot(414)
  ax1.set_ylabel('Statement-Sets')
  ax2.set_ylabel('Statements')
  ax3.set_ylabel('Predicate-Sets')
  ax4.set_ylabel('Predicates')
  ax4.set_xlabel('Wall-clock time (minutes)')

  axes = ax1, ax2, ax3, ax4

  for gen_config, test_config, color, label in plot_configs:
    print(f'Now plotting report:', label)
    plot_curve(gen_config, test_config, color, label, axes)

  ax4.legend()
  test_coverage = test_config['coverage-config']['coverage_module']
  fig_coverage.savefig(f'experiments/ISSTA_plots/baseline-vs-PCGF_{test_coverage}_violations_per-time.png')