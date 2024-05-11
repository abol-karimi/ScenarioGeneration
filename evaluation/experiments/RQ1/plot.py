#!/usr/bin/env python3

from itertools import product

import evaluation.utils.plots.baselines_vs_PCGF_per_time
import evaluation.utils.plots.baselines_vs_PCGF_per_fuzz_input


if __name__ == '__main__':

    generators = ('Atheris', 'PCGF', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'TFPP')
    coverages = ('traffic-rules', )
    RQ1_folder = f'evaluation/results/RQ1'

    coverage_filters = ('all', 'violations')
    normalizers = ('per-time', 'per-fuzz-input')

    # for each normalizer, we have a dedicated plotter
    plotter = {
        'per-time': evaluation.utils.plots.baselines_vs_PCGF_per_time,
        'per-fuzz-input': evaluation.utils.plots.baselines_vs_PCGF_per_fuzz_input
    }

    # plot visuals
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

    # each trial's results can be assessed with different metrics
    assessments = product(normalizers, coverage_filters)

    # for each (trial, assessment) combination, we generate a separate figure;
    # for each coverage type, we generate a separate subplot in the figure
    coverage_types = ('statementSet', 'statement', 'predicateSet', 'predicate')
    for (ego, coverage), (normalizer, coverage_filter) in product(trials, assessments):
        coverage_files = (f'{RQ1_folder}/{g}_{ego}_{coverage}/{coverage_filter}-coverage.json'
                            for g in generators)
        output_file = f'{RQ1_folder}/{ego}_{coverage}_{coverage_filter}_{normalizer}.png'

        plotter[normalizer].plot(coverage_files,
                                 (colors[g] for g in generators),
                                 (labels[g] for g in generators),
                                 coverage_types,
                                 output_file)
