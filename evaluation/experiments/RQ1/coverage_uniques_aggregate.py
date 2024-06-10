#!/usr/bin/env python3

from itertools import product, permutations
from datetime import timedelta
import multiprocessing
from pathlib import Path
import time
import os
import jsonpickle
import statistics

from evaluation.configs import ego_violations_coverage_filter
from scenariogen.core.coverages.coverage import PredicateSetCoverage


def identity(x):
    return x


def save_coverage_uniques(minuend_file, subtrahend_files, coverage_uniques_file):
    print(f'Calculating unique hashes for {minuend_file}...')

    subtrahend = set()
    for file in subtrahend_files:
        with open(file, 'r') as f:
            subtrahend.update(jsonpickle.decode(f.read()))

    with open(minuend_file, 'r') as f:
        minuend = set(jsonpickle.decode(f.read()))
    
    with open(coverage_uniques_file, 'w') as f:
        f.write(jsonpickle.encode(tuple(minuend-subtrahend), indent=1))


def main():
    SKIP_EXISTING = True

    generators = ('Atheris', 'PGF2', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'intersectionAgent', 'TFPP')
    trial_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    coverages = ('traffic-rules', )
    report_max_time = timedelta(hours=24)
    RQ1_folder = f'evaluation/results/RQ1'
    coverage_filters = (
        ('all-coverage', identity),
        # ('ego-violations-coverage', ego_violations_coverage_filter),
    )
    coverage_types = (
        PredicateSetCoverage,
    )

    # dependent variables
    experiments = tuple(product(generators, egos, coverages))
    assessments = tuple(product(coverage_filters, coverage_types))
    aggregates = {}

    for experiment, assessment in product(experiments, assessments):
        generator, ego, coverage = experiment
        (filter_name, filter_func), coverage_type = assessment
        uniques_lens = []
        for trial_seed in trial_seeds:
            coverage_uniques_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/{filter_name}-{coverage_type.__name__}-uniques.json'
            with open(coverage_uniques_file, 'r') as f:
                hashes = jsonpickle.decode(f.read())
            uniques_lens.append(len(hashes))

        aggregates[generator, ego, coverage] = {
            'min': min(uniques_lens),
            'median': statistics.median(uniques_lens),
            'max': max(uniques_lens),
        }
    
    with open(f'{RQ1_folder}/uniques_aggregates.json', 'w') as f:
        f.write(jsonpickle.encode(aggregates, indent=1))


if __name__ == '__main__':
    main()