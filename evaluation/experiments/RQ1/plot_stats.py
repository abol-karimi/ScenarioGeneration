#!/usr/bin/env python3

from itertools import product, permutations
import multiprocessing
import statistics

import evaluation.utils.plots.table_multi
from scenariogen.core.coverages.coverage import PredicateSetCoverage


if __name__ == '__main__':

    generators = ('Random', 'Atheris', 'PGF2', )
    egos = ('intersectionAgent', 'BehaviorAgent', 'autopilot', 'TFPP')
    coverages = ('traffic-rules', )
    RQ1_dir = f'evaluation/results/RQ1'

    stats = (
        min,
        statistics.median,
        max,
    )

    plotter = evaluation.utils.plots.table_multi
    rowLabel = {
        'Random': 'Random',
        'Atheris': 'Atheris',
        'PGF2': 'PCGF-Entropic',
    }
    color = {
        'Random': (1, 0, 0, .5),
        'Atheris': (0, 1, 0, .5),
        'PGF2': (0, 0, 1, .5),
    }
    plot_kwds = {
        'fill_alpha': 0.5,
    }

    # For each (generator, coverage) combination we make a figure showing the coverage loss for each pair of (gen_ego, test_ego)
    experiments = tuple(product(egos, coverages))

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    # for each (experiment, assessment) combination, we generate a separate figure;
    for experiment in experiments:
        (ego, coverage) = experiment
        
        entries_files = tuple(
            f'{RQ1_dir}/{generator}_{ego}_{coverage}/stats.json'
            for generator in generators
        )
        output_file = f'{RQ1_dir}/{ego}_{coverage}-stats.png'
        
        # plot_kwds['title'] = f'{ego}'
        # plot visuals
        plot_process = multiprocessing.Process(target=plotter.plot,
                                                args=(entries_files,
                                                        stats,
                                                        tuple(color[g] for g in generators),
                                                        tuple(rowLabel[g] for g in generators),
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
