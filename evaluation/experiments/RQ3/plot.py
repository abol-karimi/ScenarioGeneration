#!/usr/bin/env python3

from itertools import product
import multiprocessing
import matplotlib.cm as cm
import numpy as np

import evaluation.utils.plots.time_series
import evaluation.utils.plots.coverage_per_fuzz_input


if __name__ == '__main__':

    baseline_experiment = 'PCGF'
    baseline_egos = ('TFPP', )
    baseline_coverages = ('traffic-rules', )
    baseline_dir = f'evaluation/results/RQ1'

    test_experiment = 'PCGF_precheck'
    test_egos = (None, )
    test_coverages = ('trivial', )
    test_dir = f'evaluation/results/RQ3'

    coverage_filters = ('all', 'violations')
    normalizers = ('per-time', 'per-fuzz-input')

    baselines = tuple(product(baseline_egos, baseline_coverages))
    tests = tuple(product(test_egos, test_coverages))

        
    # each trial's results can be assessed with different metrics
    assessments = tuple(product(normalizers, coverage_filters))
    
    # for each normalizer, we have a dedicated plotter
    plotter = {
        'per-time': evaluation.utils.plots.time_series,
        'per-fuzz-input': evaluation.utils.plots.coverage_per_fuzz_input
    }

    plot_kwds = {
        'fill_alpha': 0.1,
        't_unit_sec': 60,
    }

    # colormap = cm.get_cmap('viridis')
    # palette = colormap(np.linspace(0, 1, 1+len(tuple(tests))))
    palette = ('g', 'r')

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    # for each (trial, assessment) combination, we generate a separate figure;
    # for each coverage type, we generate a separate subplot in the figure
    coverage_types = ('statementSet', 'statement', 'predicateSet', 'predicate')

    for baseline, assessment in tuple(product(baselines, assessments)):
        baseline_ego, baseline_coverage = baseline
        normalizer, coverage_filter = assessment
        coverage_files = (f'{baseline_dir}/{baseline_experiment}_{baseline_ego}_{baseline_coverage}/{coverage_filter}-coverage.json', ) \
                        + tuple(f'{test_dir}/{baseline_experiment}_{baseline_ego}_{baseline_coverage}/{test_experiment}_{test_ego}_{test_coverage}/{coverage_filter}-coverage.json'
                                for test_ego, test_coverage in tests)
        output_file = f'{test_dir}/{baseline_experiment}_{baseline_ego}_{baseline_coverage}/{coverage_filter}_{normalizer}.png'

        labels = (f'{baseline_ego}-{baseline_coverage}', ) \
                + tuple(f'{test_ego}-{test_coverage}' for test_ego, test_coverage in tests)
        plot_process = multiprocessing.Process(target=plotter[normalizer].plot,
                                                args=(coverage_files,
                                                        palette,
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
