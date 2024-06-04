#!/usr/bin/env python3

from itertools import product, permutations
from datetime import timedelta
from pathlib import Path
import time
import os
import jsonpickle

from evaluation.configs import ego_violations_coverage_filter
from evaluation.utils.utils import sum_coverage
from scenariogen.core.coverages.coverage import PredicateSetCoverage

def identity(x):
    return x

def save_coverage_sum(results_file, max_time, filter_func, coverage_type, coverage_sum_file):
    sum_cov = sum_coverage(results_file, max_time, filter_func, coverage_type)
    with open(coverage_sum_file, 'w') as f:
        f.write(jsonpickle.encode(sum_cov, indent=1))

def main():
    SKIP_EXISTING = False

    generators = ('Atheris', 'PCGF', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'intersectionAgent', 'TFPP')
    trial_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    coverages = ('traffic-rules', )
    report_max_time = timedelta(hours=24)
    RQ1_folder = f'evaluation/results/RQ1'
    coverage_filters = (
        ('all-coverage', identity),
        ('ego-violations-coverage', ego_violations_coverage_filter),
    )
    coverage_types = (
        PredicateSetCoverage,
    )

    # dependent variables
    trials = tuple(product(generators, egos, coverages, trial_seeds))
    assessments = tuple(product(coverage_filters, coverage_types))

    for trial, assessment in product(trials, assessments):
        generator, ego, coverage, trial_seed = trial
        (filter_name, filter_func), coverage_type = assessment
        results_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/results.json'
        coverage_sum_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/{filter_name}_{coverage_type.__name__}-sum.json'

        if SKIP_EXISTING and Path(coverage_sum_file).is_file():
            continue

        save_coverage_sum(results_file,
                            report_max_time.total_seconds(),
                            filter_func,
                            coverage_type,
                            coverage_sum_file)
   

if __name__ == '__main__':
    main()