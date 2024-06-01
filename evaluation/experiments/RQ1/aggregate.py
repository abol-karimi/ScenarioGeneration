#!/usr/bin/env python3

from itertools import product
from datetime import timedelta
import multiprocessing
from pathlib import Path
import time
import os

import jsonpickle
jsonpickle.load_backend('orjson')
jsonpickle.set_preferred_backend('orjson')

import evaluation.utils.aggregate_trials as aggregate_trials
from evaluation.configs import ego_violations_coverage_filter


def identity(x):
    return x


def main():
    SKIP_EXISTING = True

    generators = ('Atheris', 'PCGF', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'intersectionAgent', 'TFPP')
    trial_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    coverages = ('traffic-rules', )
    trial_timeout = timedelta(hours=24)
    sampling_period = timedelta(minutes=30)
    RQ1_folder = f'evaluation/results/RQ1'
    coverage_filters = (
        # ('all-coverage', identity),
        ('ego-violations-coverage', ego_violations_coverage_filter),
    )

    # dependent variables
    experiments = tuple(product(generators, egos, coverages))
    CPU_COUNT = len(os.sched_getaffinity(0))
    MAX_JOBS = CPU_COUNT // len(trial_seeds)
    # MAX_JOBS = 1 # when memory becomes the bottleneck

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    for experiment, cov_filter in product(experiments, coverage_filters):
        generator, ego, coverage = experiment
        filter_name, filter_func = cov_filter
        results_files = [f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/results.json'
                        for trial_seed in trial_seeds]
        aggregate_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{filter_name}.json'

        if SKIP_EXISTING and Path(aggregate_file).is_file():
            print(f'Skipping existing {aggregate_file}')
            continue

        report_process = spawn_ctx.Process(target=aggregate_trials.report,
                                            args=(results_files,
                                                    trial_timeout.total_seconds(),
                                                    filter_func,
                                                    aggregate_file,
                                                    sampling_period.total_seconds()),
                                            name=aggregate_file,
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