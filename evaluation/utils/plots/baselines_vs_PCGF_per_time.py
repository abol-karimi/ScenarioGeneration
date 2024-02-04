#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt
import importlib

from scenariogen.core.coverages.coverage import StatementCoverage, PredicateSetCoverage, PredicateCoverage


# def plot_predicate_coverage_space(axes, interval, gen_ego, gen_coverage, test_coverage):
#   fuzz_inputs_path = Path(f'experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/fuzz-inputs')
#   with open(tuple(fuzz_inputs_path.glob('*'))[0], 'r') as f:
#     seed = jsonpickle.decode(f.read())
  
#   coverage_module = importlib.import_module(f'scenariogen.core.coverages.{test_coverage}')
#   predicate_coverage_space = coverage_module.coverage_space(seed.config)

#   axes.plot(interval, (len(predicate_coverage_space),)*2, 'r--', label='Predicate-Coverage Space')


def plot_curves(config, axes):
  with open(config['coverage-file'], 'r') as f:
    result = jsonpickle.decode(f.read())

  elapsed_time = tuple(t/60 for t in result['elapsed-time'])
  ax1, ax2, ax3, ax4 = axes

  fill_alpha = .2

  ax1.plot(elapsed_time, result['statementSet_median'], config['color'], label=config['label'])
  ax1.fill_between(elapsed_time, result['statementSet_min'], result['statementSet_max'], facecolor=config['color'], alpha=fill_alpha)

  ax2.plot(elapsed_time, result['statement_median'], config['color'], label=config['label'])
  ax2.fill_between(elapsed_time, result['statement_min'], result['statement_max'], facecolor=config['color'], alpha=fill_alpha)

  ax3.plot(elapsed_time, result['predicateSet_median'], config['color'], label=config['label'])
  ax3.fill_between(elapsed_time, result['predicateSet_min'], result['predicateSet_max'], facecolor=config['color'], alpha=fill_alpha)

  ax4.plot(elapsed_time, result['predicate_median'], config['color'], label=config['label'])
  ax4.fill_between(elapsed_time, result['predicate_min'], result['predicate_max'], facecolor=config['color'], alpha=fill_alpha)


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
  ax4.set_xlabel('Wall-clock time (minutes)')

  axes = ax1, ax2, ax3, ax4

  for config in plot_config['coverage-configs']:
    print(f'Now plotting: ', config['coverage-file'])
    plot_curves(config, axes)

  # plot_predicate_coverage_space(ax4, (0, 4*60), 'TFPP', 'traffic', 'traffic-rules')

  ax4.legend()
  fig_coverage.savefig(f"{plot_config['output-folder']}/baselines-vs-PCGF_per-time.png")