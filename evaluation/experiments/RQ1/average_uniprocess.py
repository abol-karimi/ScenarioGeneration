#!/usr/bin/env python3

from itertools import product
from datetime import timedelta
from pathlib import Path
from pyinstrument import Profiler

import orjson
import jsonpickle
jsonpickle.load_backend('orjson')
jsonpickle.set_preferred_backend('orjson')


import evaluation.utils.average_coverage_uniprocess as average_coverage
from evaluation.configs import ego_violations_coverage_filter


def identity(x):
    return x


def main():
    SKIP_EXISTING = False

    generators = ('Atheris', 'PCGF', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'TFPP')
    trial_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    coverages = ('traffic-rules', )
    trial_timeout = timedelta(hours=24)
    measurement_period = timedelta(hours=1)
    RQ1_folder = f'evaluation/results/RQ1'
    coverage_filters = (
        ('all', identity),
        ('violations', ego_violations_coverage_filter),
    )

    # dependent variables
    experiments = product(generators, egos, coverages)

    for exp, cov_filter in product(experiments, coverage_filters):
        generator, ego, coverage = exp
        filter_name, filter_func = cov_filter
        results_files = [f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/results.json'
                        for trial_seed in trial_seeds]
        average_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{filter_name}-coverage.json'

        if SKIP_EXISTING and Path(average_file).is_file():
            continue

        average_coverage.report(results_files,
                                trial_timeout.total_seconds(),
                                filter_func,
                                average_file,
                                measurement_period.total_seconds())
        break
    
if __name__ == '__main__':
    profiler = Profiler()
    profiler.start()

    main()

    profiler.stop()
    profiler.write_html('average_uniprocess_orjson_iterative.html')
