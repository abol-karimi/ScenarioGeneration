#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt
import importlib

from scenariogen.core.coverages.coverage import Predicate, StatementCoverage, PredicateSetCoverage, PredicateCoverage


def plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage, plot_label, plot_color):
  coverage_file_path = Path(f'experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/test_{test_ego}_{test_coverage}/coverage.json')

  with open(coverage_file_path, 'r') as f:
    coverage = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                          coverage)['measurements']
  exe_times = tuple(int(m['exe_time']/60) for m in measurements)
  ego_violation_filter = lambda s: s.predicate in {Predicate(name) for name in {'violatesRule',
                                                                                'violatesRightOfForRule',
                                                                                'collidedWithAtTime'}} \
                                    and s.args[0] == 'ego'
  statementSet_coverages = tuple(m['statement-set-coverage'].filter(ego_violation_filter) for m in measurements)

  exe_times_acc = [exe_times[0]]
  statementSet_coverages_acc = [statementSet_coverages[0]]
  for i in range(1, len(measurements)):
    exe_times_acc.append(exe_times_acc[-1] + exe_times[i])
    statementSet_coverages_acc.append(statementSet_coverages_acc[-1] + statementSet_coverages[i])
  
  statement_coverages_acc = tuple(c.cast_to(StatementCoverage) for c in statementSet_coverages_acc)
  predicateSet_coverages_acc = tuple(c.cast_to(PredicateSetCoverage) for c in statementSet_coverages_acc)
  predicate_coverages_acc = tuple(c.cast_to(PredicateCoverage) for c in statement_coverages_acc)

  ax1.plot(exe_times_acc, tuple(len(c) for c in statementSet_coverages_acc), f'{plot_color}-', label=plot_label)
  ax2.plot(exe_times_acc, tuple(len(c) for c in statement_coverages_acc), f'{plot_color}-', label=plot_label)
  ax3.plot(exe_times_acc, tuple(len(c) for c in predicateSet_coverages_acc), f'{plot_color}-', label=plot_label)
  ax4.plot(exe_times_acc, tuple(len(c) for c in predicate_coverages_acc), f'{plot_color}-', label=plot_label)


if __name__ == '__main__':

  reports_config = (
    ('PCGF', 'TFPP', 'traffic-rules', 'TFPP', 'traffic-rules', 'PCGF', 'm'),
    ('random_search', 'TFPP', 'traffic', 'TFPP', 'traffic', 'Random search', 'b'),
    ('Atheris', 'TFPP', 'traffic-rules', 'TFPP', 'traffic-rules', 'Atheris', 'k'),
  )
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

  for experiment_type, gen_ego, gen_coverage, test_ego, test_coverage, plot_label, plot_color in reports_config:
    print(f'Now plotting report: {experiment_type, gen_ego, gen_coverage, test_ego, test_coverage}')
    plot(experiment_type, gen_ego, gen_coverage, test_ego, test_coverage, plot_label, plot_color)

  ax4.legend()
  plt.savefig(f'experiments/ISSTA_plots/baseline-vs-PCGF_{test_coverage}_violations_per-time.png')