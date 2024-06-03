#!/usr/bin/env python3

from itertools import product
from datetime import timedelta
from pathlib import Path

import jsonpickle
jsonpickle.load_backend('orjson')
jsonpickle.set_preferred_backend('orjson')


import evaluation.utils.aggregate_trials_uniprocess as aggregate_trials_uniprocess


def identity(x):
    return x


def main():
    SKIP_EXISTING = False

    generators = ('PCGF', 'PGF')
    egos = ('intersectionAgent', )
    trial_seeds = (2, 3, )
    coverages = ('traffic-rules', )
    trial_timeout = timedelta(minutes=20)
    measurement_period = timedelta(minutes=1)
    RQ1_folder = f'evaluation/results/RQ1'
    coverage_filters = (
        ('all-coverage', identity),
    )

    # dependent variables
    experiments = product(generators, egos, coverages)

    for experiment, cov_filter in product(experiments, coverage_filters):
        generator, ego, coverage = experiment
        filter_name, filter_func = cov_filter
        results_files = [f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/results.json'
                        for trial_seed in trial_seeds]
        aggregate_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{filter_name}.json'

        if SKIP_EXISTING and Path(aggregate_file).is_file():
            continue

        aggregate_trials_uniprocess.report(results_files,
                                            trial_timeout.total_seconds(),
                                            filter_func,
                                            aggregate_file,
                                            measurement_period.total_seconds())


if __name__ == '__main__':
    main()
