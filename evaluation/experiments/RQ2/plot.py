#!/usr/bin/env python3

from itertools import product
import multiprocessing

import evaluation.utils.plots.coverage_per_time
import evaluation.utils.plots.coverage_per_fuzz_input


if __name__ == '__main__':

    generators = ('PCGF', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'TFPP')
    coverages = ('traffic-rules', )
    RQ1_dir = f'evaluation/results/RQ1'
    RQ2_dir = f'evaluation/results/RQ2'

    coverage_filters = ('all', 'violations')
    normalizers = ('per-time', 'per-fuzz-input')

    # for each normalizer, we have a dedicated plotter
    plotter = {
        'per-time': evaluation.utils.plots.coverage_per_time,
        'per-fuzz-input': evaluation.utils.plots.coverage_per_fuzz_input
    }

    plot_kwds = {
        'fill_alpha': 0.1,
        't_unit_sec': 60,
    }

    # each (generator, gen_ego, coverage) combination is a trial for studying the effect using a different ego for testing
    experiments = product(generators, egos, coverages)

    # each trial's results can be assessed with different metrics
    assessments = product(normalizers, coverage_filters)

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    # for each (trial, assessment) combination, we generate a separate figure;
    # for each coverage type, we generate a separate subplot in the figure
    coverage_types = ('statementSet', 'statement', 'predicateSet', 'predicate')
    for (generator, gen_ego, coverage), (normalizer, coverage_filter) in product(experiments, assessments):
        test_egos = tuple(e for e in egos if e != gen_ego)
        coverage_files = (f'{RQ1_dir}/{generator}_{gen_ego}_{coverage}/{coverage_filter}-coverage.json', ) \
                        + tuple(f'{RQ2_dir}/{generator}_{gen_ego}_{coverage}/{test_ego}/{coverage_filter}-coverage.json'
                                for test_ego in test_egos)
        output_file = f'{RQ2_dir}/{gen_ego}_{coverage}_{coverage_filter}_{normalizer}.png'
        
        # plot visuals
        colors = ('g', 'r', 'b')
        labels = (f'{gen_ego} (gen)', ) + test_egos

        plot_process = multiprocessing.Process(target=plotter[normalizer].plot,
                                                args=(coverage_files,
                                                        colors,
                                                        labels,
                                                        coverage_types,
                                                        output_file,
                                                        plot_kwds
                                                    ),
                                                name=output_file,
                                                daemon=False
                                                )

        plot_process.start()
        processes.append(plot_process)
    
    for p in processes:
        p.join()
        print(f'{p.name} exited with exitcode {p.exitcode}.')
