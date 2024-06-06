#!/usr/bin/env python3

from itertools import product
import multiprocessing

import evaluation.utils.plots.time_series


def fuzz_inputs(aggregate):
    return aggregate['fuzz-inputs']


def predicates(aggregate):
    return aggregate['predicates']


def predicateSets(aggregate):
    return aggregate['predicateSets']


def statements(aggregate):
    return aggregate['statements']


def statementSets(aggregate):
    return aggregate['statementSets']


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

    # generators = ('PGF2', 'Atheris', 'Random', )
    generators = ('PCGF', 'PGF2', 'PGF', )
    egos = ('autopilot', 'intersectionAgent')
    coverages = ('traffic-rules', )
    RQ1_folder = f'evaluation/results/RQ1'

    coverage_filters = (
        'all-coverage',
        # 'ego-violations-coverage',
        )

    metrics = (
        # statementSets,
        # statementSets_per_fuzz_input,
        # statements,
        # statements_per_fuzz_input,
        predicateSets,
        predicateSets_per_fuzz_input,
        # predicates,
        # predicates_per_fuzz_input,
    )
    metric_name = {
        predicateSets: 'Predicate-Sets',
        predicateSets_per_fuzz_input: 'Predicate-Sets-per-Fuzz-Input',
    }
    stats = (
        'range',
        'median',
    )
    
    plotter = evaluation.utils.plots.time_series

    # plot visuals
    plot_kwds = {
        'fill_alpha': 0.1,
        't_unit_sec': 3600,
    }   
    color = {
        # for Predicate-Set-Coverage Guided vs baselines
        'PGF2': 'r',
        'Atheris': 'g',
        'Random': 'b',
        # for comparison of power schedules
        'PCGF': 'g',
        'PGF': 'b',
    }
    label = {
        'PCGF': 'PCGF-AFLFast',
        'PGF2': 'PCGF-Entropic',
        'PGF': 'PCGF-Entropic-MixedFeedback',
        'Atheris': 'Atheris',
        'Random': 'Random',
    }

    # each (ego, coverage) combination is a trial for comparing the generators
    trials = product(egos, coverages)

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    # for each (trial, coverage_filter) combination, we generate a separate figure;
    # for each metric, we generate a separate subplot in the figure
    for trial, coverage_filter in product(trials, coverage_filters):
        ego, coverage = trial
        aggregate_files = tuple(f'{RQ1_folder}/{g}_{ego}_{coverage}/{coverage_filter}.json'
                                for g in generators)
        labels = tuple(label[g] for g in generators)
        metric_names = ",".join(metric_name[m] for m in metrics)
        output_file = f'{RQ1_folder}/({",".join(labels)})_{ego}_{coverage}_{coverage_filter}_({metric_names}).png'
        plot_kwds['title'] = f'{ego}_{coverage}_{coverage_filter}'
        colors = tuple(color[g] for g in generators)
        plot_process = multiprocessing.Process(
                            target=plotter.plot,
                            args=(aggregate_files,
                                    {metric_name[m]:m for m in metrics},
                                    stats,
                                    colors,
                                    labels,
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
