#!/usr/bin/env python3

from itertools import product
import multiprocessing

import evaluation.utils.plots.time_series


def coverage_per_fuzz_input(aggregate, cov_type):
    metric = []
    for trials_statements, trials_inputs in zip(aggregate[cov_type], aggregate['fuzz-inputs']):
        metric.append(tuple(s/i if i > 0 else 0 for s,i in zip(trials_statements, trials_inputs)))

    return metric


def predicates_per_fuzz_input(aggregate):
    return coverage_per_fuzz_input(aggregate, 'predicates')


def predicateSets_per_fuzz_input(aggregate):
    return coverage_per_fuzz_input(aggregate, 'predicateSets')


def statements_per_fuzz_input(aggregate):
    return coverage_per_fuzz_input(aggregate, 'statements')


def statementSets_per_fuzz_input(aggregate):
    return coverage_per_fuzz_input(aggregate, 'statementSets')


if __name__ == '__main__':

    generators = ('PCGF', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'TFPP')
    coverages = ('traffic-rules', )
    RQ1_folder = f'evaluation/results/RQ1'

    coverage_filters = ('all-coverage', )

    metrics = (
        statements_per_fuzz_input,
        predicateSets_per_fuzz_input,
    )
    stats = (
        'range',
        'median',
    )
    
    plotter = evaluation.utils.plots.time_series

    # plot visuals
    plot_kwds = {
        'fill_alpha': 0.1,
        't_unit_sec': 60,
    }   
    colors = {
        'PCGF': 'g',
        'Atheris': 'b',
        'Random': 'r',
    }
    labels = {
        'PCGF': 'PCGF',
        'Atheris': 'Atheris',
        'Random': 'Random',
    }

    # each (ego, coverage) combination is a trial for comparing the generators
    trials = product(egos, coverages)

    # each trial's results can be plotted w.r.t to different assessment criteria
    assessments = product(coverage_filters, metrics)

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    # for each (trial, assessment) combination, we generate a separate figure;
    # for each metric, we generate a separate subplot in the figure
    for trial, coverage_filter in product(trials, coverage_filters):
        ego, coverage = trial
        aggregate_files = tuple(f'{RQ1_folder}/{g}_{ego}_{coverage}/{coverage_filter}.json'
                                for g in generators)
        output_file = f'{RQ1_folder}/{ego}_{coverage}_{coverage_filter}.png'

        plot_process = multiprocessing.Process(
                            target=plotter.plot,
                            args=(aggregate_files,
                                    metrics,
                                    stats,
                                    (colors[g] for g in generators),
                                    (labels[g] for g in generators),
                                    plot_kwds,
                                    output_file,
                                    ),
                            name=output_file,
                            daemon=False
                            )
        plot_process.start()
        processes.append(plot_process)
    
    for p in processes:
        p.join()
        print(f'{p.name} exited with exitcode {p.exitcode}.')
