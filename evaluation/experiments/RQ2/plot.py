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
    # generators = ('Atheris', 'Random')
    egos = ('intersectionAgent', 'BehaviorAgent', 'autopilot', 'TFPP')
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
    metric_name = {
        predicateSets_percentage: 'Coverage-Percentage',
    }
    stats = (
        min,
        statistics.median,
        max,
    )

    plotter = evaluation.utils.plots.table
    colLabel = {
        'intersectionAgent': 'SCENIC agent',
        'BehaviorAgent': 'BehaviorAgent',
        'autopilot': 'Autopilot',
        'TFPP': 'TF++',
    }
    rowLabel = {
        'intersectionAgent': 'SCENIC agent',
        'BehaviorAgent': 'BehaviorAgent',
        'autopilot': 'Autopilot',
        'TFPP': 'TF++',
    }
    colors = {
        'intersectionAgent': (1, 0, 0, .5),
        'autopilot': (0, 1, 0, .5),
        'BehaviorAgent': (0, 0, 1, .5),
        'TFPP': 'w'
    }
    plot_kwds = {
        'fill_alpha': 0.5,
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
        output_file = f'{RQ2_dir}/{generator}_{coverage}_{coverage_filter}_{coverage_type}_{metric_name[metric]}.png'
        
        plot_kwds['title'] = f'{generator}'
        plot_kwds['ylabel'] = metric_name[metric]
        # plot visuals
        plot_process = multiprocessing.Process(target=plotter.plot,
                                                args=(entries_files,
                                                        metric,
                                                        stats,
                                                        colors,
                                                        colLabel,
                                                        rowLabel,
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
