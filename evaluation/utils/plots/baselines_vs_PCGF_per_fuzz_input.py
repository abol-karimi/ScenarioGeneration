#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt
import importlib

from scenariogen.core.coverages.coverage import StatementCoverage, PredicateSetCoverage, PredicateCoverage


def plot_predicate_coverage_space(gen_config, test_config, axes, interval):
  fuzz_input_path = tuple(Path(gen_config['fuzz-inputs-folder']).glob('*'))[0]
  with open(fuzz_input_path, 'r') as f:
    seed = jsonpickle.decode(f.read())
  
  test_coverage = test_config['coverage-config']['coverage-module']
  coverage_module = importlib.import_module(f'scenariogen.core.coverages.{test_coverage}')
  predicate_coverage_space = coverage_module.coverage_space(seed.config)

  axes.plot(interval, (len(predicate_coverage_space),)*2, 'r--', label='Predicate-Coverage Space')


def plot_curve(gen_config, test_config, plot_color, plot_label, axes):
  coverage_file_path = Path(test_config['output-folder'])/'coverage.json'

  with open(coverage_file_path, 'r') as f:
    coverage = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                          coverage)['measurements']
  new_fuzz_input_files = tuple(m['new-fuzz-input-files'] for m in measurements)
  statementSet_coverages = tuple(m['statement-set-coverage'] for m in measurements)

  new_fuzz_input_files_acc = [new_fuzz_input_files[0]]
  statementSet_coverages_acc = [statementSet_coverages[0]]
  for i in range(1, len(measurements)):
    new_fuzz_input_files_acc.append(new_fuzz_input_files_acc[-1].union(new_fuzz_input_files[i]))
    statementSet_coverages_acc.append(statementSet_coverages_acc[-1] + statementSet_coverages[i])
  
  statement_coverages_acc = tuple(c.cast_to(StatementCoverage) for c in statementSet_coverages_acc)
  predicateSet_coverages_acc = tuple(c.cast_to(PredicateSetCoverage) for c in statementSet_coverages_acc)
  predicate_coverages_acc = tuple(c.cast_to(PredicateCoverage) for c in statement_coverages_acc)

  x_axis = tuple(len(files) for files in new_fuzz_input_files_acc)

  ax1, ax2, ax3, ax4 = axes
  ax1.plot(x_axis, tuple(len(c) for c in statementSet_coverages_acc), f'{plot_color}-', label=plot_label)
  ax2.plot(x_axis, tuple(len(c) for c in statement_coverages_acc), f'{plot_color}-', label=plot_label)
  ax3.plot(x_axis, tuple(len(c) for c in predicateSet_coverages_acc), f'{plot_color}-', label=plot_label)
  ax4.plot(x_axis, tuple(len(c) for c in predicate_coverages_acc), f'{plot_color}-', label=plot_label)


def plot(plot_config):
  fig_coverage = plt.figure(layout='constrained')

  # Empty axes used as a container of subplots
  ax = fig_coverage.add_subplot(111)
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
  ax4.set_xlabel('Number of fuzz-inputs generated')

  axes = ax1, ax2, ax3, ax4

  for gen_config, test_config, color, label in plot_config:
    print(f'Now plotting report:', label)
    plot_curve(gen_config, test_config, color, label, axes)

  fuzz_inputs_nums = [len(tuple(Path(test_config['fuzz_inputs-folder']).glob('*')))
                      for _, test_config, _, _ in plot_config]
  max_fuzz_inputs_num = max(fuzz_inputs_nums)

  plot_predicate_coverage_space(ax4, (0, max_fuzz_inputs_num), 'TFPP', 'traffic', 'traffic-rules')

  ax4.legend()
  test_coverage = test_config['coverage-config']['coverage-module']
  fig_coverage.savefig(f'experiments/ISSTA_plots/baselines-vs-PCGF_{test_coverage}_per-fuzz-input.png')