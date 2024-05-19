#!/usr/bin/env python3

from itertools import product
from datetime import timedelta
import multiprocessing
from pathlib import Path
import time
import os

import evaluation.utils.average_coverage as average_coverage
from evaluation.configs import ego_violations_coverage_filter


def identity(x):
    return x


def main():
    SKIP_EXISTING = False

    baseline_experiment = 'PCGF'
    baseline_egos = ('TFPP', )
    baseline_coverages = ('traffic-rules', )


    test_experiment = 'PCGF_precheck'
    test_egos = (None, )
    test_coverages = ('trivial', )
    test_dir = f'evaluation/results/RQ3'


    trial_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    trial_timeout = timedelta(hours=24)
    sampling_period = timedelta(minutes=10)
    coverage_filters = (
        ('all', identity),
        ('violations', ego_violations_coverage_filter),
    )

    # dependent variables
    baselines = tuple(product(baseline_egos, baseline_coverages))
    tests = tuple(product(test_egos, test_coverages))
    experiments = tuple(product(baselines, tests))

    CPU_COUNT = len(os.sched_getaffinity(0))
    MAX_AVG_JOBS = CPU_COUNT // len(trial_seeds)

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    for experiment, cov_filter in tuple(product(experiments, coverage_filters)):
        (baseline_ego, baseline_coverage), (test_ego, test_coverage) = experiment
        filter_name, filter_func = cov_filter
        results_files = [f'{test_dir}/{baseline_experiment}_{baseline_ego}_{baseline_coverage}/{test_experiment}_{test_ego}_{test_coverage}/{trial_seed}/results.json'
                        for trial_seed in trial_seeds]
        average_file = f'{test_dir}/{baseline_experiment}_{baseline_ego}_{baseline_coverage}/{test_experiment}_{test_ego}_{test_coverage}/{filter_name}-coverage.json'

        if SKIP_EXISTING and Path(average_file).is_file():
            continue

        report_process = spawn_ctx.Process(target=average_coverage.report,
                                            args=(results_files,
                                                    trial_timeout.total_seconds(),
                                                    filter_func,
                                                    average_file,
                                                    sampling_period.total_seconds()),
                                            name=average_file,
                                            daemon=False
                                            )
        report_process.start()
        processes.append(report_process)

        while sum(1 for p in processes if p.is_alive()) >= MAX_AVG_JOBS:
            time.sleep(10)
    
    for p in processes:
        p.join()
        print(f'{p.name} exited with code {p.exitcode}.')

if __name__ == '__main__':
    main()