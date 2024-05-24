#!/usr/bin/env python3

""" Generate the coverage reports """

import jsonpickle
import matplotlib.pyplot as plt
import statistics


def plot_median(aggregate, metric, subplot, color, label, kwds):
    elapsed_time = tuple(t/kwds['t_unit_sec'] for t in aggregate['elapsed-time'])
    metric_aggregate = metric(aggregate)
    metric_median = tuple(statistics.median(m) for m in metric_aggregate)
    subplot.plot(elapsed_time, metric_median, color, label=label)


def plot_range(aggregate, metric, subplot, color, label, kwds):
    elapsed_time = tuple(t/kwds['t_unit_sec'] for t in aggregate['elapsed-time'])
    metric_aggregate = metric(aggregate)
    metric_min = tuple(min(m) for m in metric_aggregate)
    metric_max = tuple(max(m) for m in metric_aggregate)
    subplot.fill_between(elapsed_time, metric_min, metric_max, facecolor=color, alpha=kwds['fill_alpha'])


def plot_metrics_stat(aggregate, metric, stat, subplot, color, label, kwds):
    if stat == 'median':
        plot_median(aggregate, metric, subplot, color, label, kwds)
    elif stat == 'range':
        plot_range(aggregate, metric, subplot, color, label, kwds)
    else:
        raise ValueError(f'Unknown statistic: {stat}')


def plot_metrics(aggregate_file, metrics, stats, subplots, graph_color, graph_label, graph_kwds):
    with open(aggregate_file, 'r') as f:
        aggregate = jsonpickle.decode(f.read())

    for metric, subplot in zip(metrics, subplots):
        for stat in stats:
            plot_metrics_stat(aggregate, metric, stat, subplot, graph_color, graph_label, graph_kwds)


def plot(aggregate_files, metrics, stats, colors, labels, kwds, output_file):
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

    subplots = []
    for i, metric in enumerate(metrics):
        ax = fig_coverage.add_subplot(len(metrics), 1, i+1)
        ax.set_ylabel(metric.__name__)
        subplots.append(ax)
    subplots[-1].set_xlabel('Wall-clock time (hours)')

    for aggregate_file, color, label in zip(aggregate_files, colors, labels):
        print(f'Now plotting: ', aggregate_file)
        plot_metrics(aggregate_file, metrics, stats, subplots, color, label, kwds)

    subplots[-1].legend()
    fig_coverage.savefig(output_file)