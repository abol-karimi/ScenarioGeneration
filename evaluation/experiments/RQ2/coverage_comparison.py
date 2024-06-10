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

def save_coverage_comparison(trials_files, comparison_file):
    trials_comparison = []
    for gen, test in trials_files:
        with open(gen, 'r') as f:
            gen_coverage = jsonpickle.decode(f.read())
        with open(test, 'r') as f:
            test_coverage = jsonpickle.decode(f.read())
        trials_comparison.append((gen_coverage, test_coverage))

    with open(comparison_file, 'w') as f:
        f.write(jsonpickle.encode(tuple(trials_comparison), indent=1))

def main():
    SKIP_EXISTING = True

    generators = ('Atheris', 'PCGF', 'Random')
    egos = ('autopilot', 'BehaviorAgent', 'intersectionAgent', 'TFPP')
    trial_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    coverages = ('traffic-rules', )
    report_max_time = timedelta(hours=24)
    RQ1_folder = f'evaluation/results/RQ1'
    RQ2_folder = f'evaluation/results/RQ2'
    coverage_filters = (
        ('all-coverage', identity),
        # ('ego-violations-coverage', ego_violations_coverage_filter),
    )
    coverage_types = (
        PredicateSetCoverage,
    )

    # dependent variables
    experiments = tuple(product(generators, permutations(egos, r=2), coverages))
    assessments = tuple(product(coverage_filters, coverage_types))
    CPU_COUNT = len(os.sched_getaffinity(0))
    MAX_JOBS = CPU_COUNT

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    for experiment, assessment in product(experiments, assessments):
        generator, (gen_ego, test_ego), coverage = experiment
        (filter_name, filter_func), coverage_type = assessment

        comparison_file = f'{RQ2_folder}/{generator}_{gen_ego}_{coverage}/{test_ego}/{filter_name}-{coverage_type.__name__}-comparison.json'
        if SKIP_EXISTING and Path(comparison_file).is_file():
            print(f'Skipping existing {comparison_file}.')
            continue

        trials_files = tuple(
            (
                f'{RQ1_folder}/{generator}_{gen_ego}_{coverage}/{trial_seed}/{filter_name}-{coverage_type.__name__}-sum.json',
                f'{RQ2_folder}/{generator}_{gen_ego}_{coverage}/{test_ego}/{trial_seed}/{filter_name}-{coverage_type.__name__}-sum.json'
            )
            for trial_seed in trial_seeds
        )

        report_process = spawn_ctx.Process(target=save_coverage_comparison,
                                            args=(trials_files,
                                                    comparison_file),
                                            name=comparison_file,
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