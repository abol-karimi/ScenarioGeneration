#!/usr/bin/env python3

from itertools import product, permutations
from datetime import timedelta
import multiprocessing
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
    RQ2_folder = f'evaluation/results/RQ2'
    coverage_filters = (
        ('all-coverage', identity),
        # ('ego-violations-coverage', ego_violations_coverage_filter),
    )
    coverage_types = (
        PredicateSetCoverage,
    )

    # dependent variables
    trials = tuple(product(generators, permutations(egos, r=2), coverages, trial_seeds))
    assessments = tuple(product(coverage_filters, coverage_types))
    CPU_COUNT = len(os.sched_getaffinity(0))
    MAX_JOBS = CPU_COUNT

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    for trial, assessment in product(trials, assessments):
        generator, (gen_ego, test_ego), coverage, trial_seed = trial
        (filter_name, filter_func), coverage_type = assessment
        results_file = f'{RQ2_folder}/{generator}_{gen_ego}_{coverage}/{test_ego}/{trial_seed}/results.json'
        coverage_sum_file = f'{RQ2_folder}/{generator}_{gen_ego}_{coverage}/{test_ego}/{trial_seed}/{filter_name}-{coverage_type.__name__}-sum.json'

        if SKIP_EXISTING and Path(coverage_sum_file).is_file():
            continue

        report_process = spawn_ctx.Process(target=save_coverage_sum,
                                            args=(results_file,
                                                    report_max_time.total_seconds(),
                                                    filter_func,
                                                    coverage_type,
                                                    coverage_sum_file),
                                            name=coverage_sum_file,
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