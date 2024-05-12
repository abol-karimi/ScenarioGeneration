#!/usr/bin/env python3

""" Generate the coverage reports """

import jsonpickle
import matplotlib.pyplot as plt


# def plot_predicate_coverage_space(axes, interval, gen_ego, gen_coverage, test_coverage):
#   fuzz_inputs_path = Path(f'experiments/{experiment_type}/gen_{gen_ego}_{gen_coverage}/fuzz-inputs')
#   with open(tuple(fuzz_inputs_path.glob('*'))[0], 'r') as f:
#     seed = jsonpickle.decode(f.read())
  
#   coverage_module = importlib.import_module(f'scenariogen.core.coverages.{test_coverage}')
#   predicate_coverage_space = coverage_module.coverage_space(seed.config)

#   axes.plot(interval, (len(predicate_coverage_space),)*2, 'r--', label='Predicate-Coverage Space')


def plot_curves(coverage_file, color, label, axes, coverage_types, t_unit_sec=3600, fill_alpha=.1):
  with open(coverage_file, 'r') as f:
    result = jsonpickle.decode(f.read())

  elapsed_time = tuple(t/t_unit_sec for t in result['elapsed-time'])

  for ax, cov_type in zip(axes, coverage_types):
    ax.plot(elapsed_time, result[f'{cov_type}_median'], color, label=label)
    ax.fill_between(elapsed_time, result[f'{cov_type}_min'], result[f'{cov_type}_max'], facecolor=color, alpha=fill_alpha)


def plot(coverage_files, colors, labels, coverage_types, output_file):
  fig_coverage = plt.figure(layout='constrained')

  # Empty axes used as a container of subplots
  ax = fig_coverage.add_subplot(111)
  ax.spines['top'].set_color('none')
  ax.spines['bottom'].set_color('none')
  ax.spines['left'].set_color('none')
  ax.spines['right'].set_color('none')
  ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)

  axes = []
  for i, coverage_type in enumerate(coverage_types):
    ax = fig_coverage.add_subplot(len(coverage_types), 1, i+1)
    ax.set_ylabel(f'{coverage_type}s')
    axes.append(ax)
  axes[-1].set_xlabel('Wall-clock time (hours)')

  for coverage_file, color, label in zip(coverage_files, colors, labels):
    print(f'Now plotting: ', coverage_file)
    plot_curves(coverage_file, color, label, axes, coverage_types)

  # plot_predicate_coverage_space(ax4, (0, 4*60), 'TFPP', 'traffic', 'traffic-rules')

  axes[-1].legend()
  fig_coverage.savefig(output_file)