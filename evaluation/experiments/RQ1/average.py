#!/usr/bin/env python3

from itertools import product
from datetime import timedelta

import evaluation.utils.average_coverage as average_coverage
from evaluation.configs import ego_violations_coverage_filter


if __name__ == '__main__':

    generators = ('Atheris', 'PCGF', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'TFPP')
    trial_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    coverages = ('traffic-rules', )
    trial_timeout = timedelta(hours=24)
    RQ1_folder = f'evaluation/results/RQ1'
    coverage_filters = (
        ('all', lambda s: s),
        ('violations', ego_violations_coverage_filter),
    )

    # dependent variables
    experiments = product(generators, egos, coverages)

    for exp, filter in product(experiments, coverage_filters):
        generator, ego, coverage = exp
        filter_name, filter_func = filter
        results_files = [f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/results.json'
                        for trial_seed in trial_seeds]
        average_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{filter_name}-coverage.json'
        average_coverage.report(results_files,
                                trial_timeout.total_seconds(),
                                filter_func,
                                average_file)
