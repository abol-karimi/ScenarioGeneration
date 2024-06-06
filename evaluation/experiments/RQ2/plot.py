#!/usr/bin/env python3

from itertools import product, permutations
import multiprocessing
import statistics

import evaluation.utils.plots.table
from scenariogen.core.coverages.coverage import PredicateSetCoverage


def predicateSets_percentage(comparison_trial):
    gen_coverage, test_coverage = comparison_trial
    num = len(test_coverage.cast_to(PredicateSetCoverage))
    denom = len(gen_coverage.cast_to(PredicateSetCoverage))
    return int(num / denom * 100)


if __name__ == '__main__':

    generators = ('Atheris', 'PCGF', 'Random')
    # generators = ('Atheris', )
    egos = ('autopilot', 'BehaviorAgent', 'intersectionAgent', 'TFPP')
    coverages = ('traffic-rules', )
    RQ1_dir = f'evaluation/results/RQ1'
    RQ2_dir = f'evaluation/results/RQ2'

    coverage_filters = ('all-coverage', )
    coverage_types = ('PredicateSetCoverage', )
    metrics = (
        # statementSets_percentage,
        # statements_percentage,
        predicateSets_percentage,
        # predicates_percentage,
    )
    stats = (
        min,
        statistics.median,
        max,
    )

    plotter = evaluation.utils.plots.table
    colLabels = egos
    rowLabels = egos
    colors = {
        'autopilot': "#1f77b4", 
        'BehaviorAgent': "#ff7f0e", 
        'intersectionAgent': "#2ca02c", 
        'TFPP': "#d62728"
    }
    plot_kwds = {
    }

    # For each (generator, coverage) combination we make a figure showing the coverage loss for each pair of (gen_ego, test_ego)
    experiments = tuple(product(generators, coverages))
    assessments = tuple(product(coverage_filters, coverage_types, metrics))

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    # for each (experiment, assessment) combination, we generate a separate figure;
    for experiment, assessment in product(experiments, assessments):
        (generator, coverage) = experiment
        (coverage_filter, coverage_type, metric) = assessment
        
        entries_files = {
            (gen_ego, test_ego): f'{RQ2_dir}/{generator}_{gen_ego}_{coverage}/{test_ego}/{coverage_filter}-{coverage_type}-comparison.json'
            for gen_ego, test_ego in permutations(egos, r=2)
        }
        output_file = f'{RQ2_dir}/{generator}_{coverage}_{coverage_filter}_{coverage_type}_{metric.__name__}.png'
        
        # plot visuals
        plot_process = multiprocessing.Process(target=plotter.plot,
                                                args=(entries_files,
                                                        metric,
                                                        stats,
                                                        colors,
                                                        colLabels,
                                                        rowLabels,
                                                        plot_kwds,
                                                        output_file
                                                    ),
                                                name=output_file,
                                                daemon=False
                                                )

        plot_process.start()
        processes.append(plot_process)
    
    for p in processes:
        p.join()
        print(f'{p.name} exited with exitcode {p.exitcode}.')
