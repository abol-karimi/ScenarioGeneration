#!/usr/bin/env python3

""" Generate the coverage reports """

import jsonpickle
import matplotlib.pyplot as plt


def plot_curves(coverage_file, color, label, axes, coverage_types, kwds):
    with open(coverage_file, 'r') as f:
        result = jsonpickle.decode(f.read())

    for ax, cov_type in zip(axes, coverage_types):
        ax.plot(result['fuzz-inputs-num_median'], result[f'{cov_type}_median'], color, label=label)
        ax.fill_between(result['fuzz-inputs-num_median'],
                        result[f'{cov_type}_min'],
                        result[f'{cov_type}_max'],
                        facecolor=color,
                        alpha=kwds['fill_alpha'])


def plot(coverage_files, colors, labels, coverage_types, output_file, kwds):
    # fig_coverage = plt.figure(layout='constrained')
    fig_coverage = plt.figure(layout='tight')

    # Empty axes used as a container of subplots
    ax = fig_coverage.add_subplot(111)
    ax.set_title(output_file, fontsize=10)
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
    axes[-1].set_xlabel('Median number of valid fuzz-inputs generated')

    for coverage_file, color, label in zip(coverage_files, colors, labels):
        print(f'Now plotting: ', coverage_file)
        plot_curves(coverage_file, color, label, axes, coverage_types, kwds)

    axes[-1].legend()
    fig_coverage.savefig(output_file)