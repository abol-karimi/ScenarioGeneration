#!/usr/bin/env python3

from itertools import product
from datetime import timedelta
import multiprocessing
from pathlib import Path
import time

import evaluation.utils.average_coverage as average_coverage
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
    sampling_period = timedelta(minutes=10)
    RQ1_folder = f'evaluation/results/RQ1'
    coverage_filters = (
        ('all', identity),
        ('violations', ego_violations_coverage_filter),
    )

    # dependent variables
    experiments = product(generators, egos, coverages)

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    for exp, cov_filter in product(experiments, coverage_filters):
        generator, ego, coverage = exp
        filter_name, filter_func = cov_filter
        results_files = [f'{RQ1_folder}/{generator}_{ego}_{coverage}/{trial_seed}/results.json'
                        for trial_seed in trial_seeds]
        average_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/{filter_name}-coverage.json'

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

        while sum(1 for p in processes if p.is_alive()) > 3:
            time.sleep(10)
    
    for p in processes:
        p.join()
        print(f'{p.name} exited with code {p.exitcode}.')

if __name__ == '__main__':
    main()