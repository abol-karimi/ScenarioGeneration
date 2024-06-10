#!/usr/bin/env python3

from itertools import product, permutations
from datetime import timedelta
import multiprocessing
from pathlib import Path
import time
import os
import jsonpickle

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
    trials = tuple(product(generators, egos, coverages, trial_seeds))
    assessments = tuple(product(coverage_filters, coverage_types))
    CPU_COUNT = len(os.sched_getaffinity(0))
    MAX_JOBS = CPU_COUNT
    MAX_JOBS = 10

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    for trial, assessment in product(trials, assessments):
        generator, ego, coverage, trial_seed = trial
        (filter_name, filter_func), coverage_type = assessment
        trial_dir = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}'
        minuend_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/{filter_name}-{coverage_type.__name__}-hashes.json'
        subtrahend_files = tuple(
            f'{RQ1_folder}/{g}_{ego}_{coverage}/{trial_seed}/{filter_name}-{coverage_type.__name__}-hashes.json'
            for g in set(generators) - {generator}
        )
        print(f'minuend_file: {minuend_file}, subtrahend_files: {subtrahend_files}')
        coverage_uniques_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/{filter_name}-{coverage_type.__name__}-uniques.json'

        if SKIP_EXISTING and Path(coverage_uniques_file).is_file():
            print(f'Skipping existing {coverage_uniques_file}')
            continue

        report_process = spawn_ctx.Process(target=save_coverage_uniques,
                                            args=(minuend_file,
                                                    subtrahend_files,
                                                    coverage_uniques_file),
                                            name=coverage_uniques_file,
                                            daemon=False
                                            )
        report_process.start()
        processes.append(report_process)

        while sum(1 for p in processes if p.is_alive()) >= MAX_JOBS:
            time.sleep(10)
    
    for p in processes:
        p.join()
        print(f'{p.name} exited with code {p.exitcode}.')

if __name__ == '__main__':
    main()