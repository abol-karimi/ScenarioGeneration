#!/usr/bin/env python3

from itertools import product, permutations
from datetime import timedelta
import multiprocessing
from pathlib import Path
import time
import os

import evaluation.utils.aggregate_trials as aggregate_trials
from evaluation.configs import ego_violations_coverage_filter


def identity(x):
    return x


def main():
    SKIP_EXISTING = False

    generators = ('Atheris', 'PCGF', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'TFPP')
    trial_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    coverages = ('traffic-rules', )
    report_max_time = timedelta(hours=24)
    sampling_period = timedelta(minutes=10)
    RQ2_folder = f'evaluation/results/RQ2'
    coverage_filters = (
        ('all', identity),
        ('violations', ego_violations_coverage_filter),
    )

    # dependent variables
    experiments = product(generators, permutations(egos, r=2), coverages)
    CPU_COUNT = len(os.sched_getaffinity(0))
    MAX_AVG_JOBS = CPU_COUNT // len(trial_seeds)

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    for exp, cov_filter in product(experiments, coverage_filters):
        generator, (gen_ego, test_ego), coverage = exp
        filter_name, filter_func = cov_filter
        results_files = [f'{RQ2_folder}/{generator}_{gen_ego}_{coverage}/{test_ego}/{trial_seed}/results.json'
                        for trial_seed in trial_seeds]
        average_file = f'{RQ2_folder}/{generator}_{gen_ego}_{coverage}/{test_ego}/{filter_name}-coverage.json'

        if SKIP_EXISTING and Path(average_file).is_file():
            continue

        report_process = spawn_ctx.Process(target=aggregate_trials.report,
                                            args=(results_files,
                                                    report_max_time.total_seconds(),
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