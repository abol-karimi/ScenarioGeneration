#!/usr/bin/env python3

from itertools import product, permutations
from datetime import timedelta
import multiprocessing
from pathlib import Path
import time
import os

import jsonpickle
jsonpickle.load_backend('orjson')
jsonpickle.set_preferred_backend('orjson')

from scenariogen.core.coverages.coverage import PredicateSetCoverage


def save_stats(experiment, trial_seeds, stats, stats_file):
    generator, ego, coverage = experiment
    stats_data = {}
    for stat, stat_func in stats.items():
        stat_trials = []
        for trial_seed in trial_seeds:
            trial_folder = f'evaluation/results/RQ1/{generator}_{ego}_{coverage}/{trial_seed}'
            trial_stat = stat_func(trial_folder)
            stat_trials.append(trial_stat)
        stats_data[stat] = tuple(stat_trials)
    with open(stats_file, 'w') as f:
        f.write(jsonpickle.encode(stats_data, indent=1))
    
    print(f'Finished saving {stats_file}.')


def total_valid_fuzz_inputs(trial_folder):
    fuzz_inputs_path = Path(trial_folder) / 'fuzz-inputs'
    return len(tuple(fuzz_inputs_path.glob('*')))


def total_ego_violations(trial_folder):
    ego_violations_sum_file = Path(trial_folder) / 'ego-violations-coverage-PredicateSetCoverage-sum.json'
    with open(ego_violations_sum_file, 'r') as f:
        ego_violations_sum = jsonpickle.decode(f.read())

    return len(ego_violations_sum)


def total_PredicateSetCoverage(trial_folder):
    coverage_sum_file = Path(trial_folder) / 'all-coverage-PredicateSetCoverage-sum.json'
    with open(coverage_sum_file, 'r') as f:
        coverage_sum = jsonpickle.decode(f.read())

    return len(coverage_sum)


def main():
    SKIP_EXISTING = True

    generators = ('Atheris', 'PGF2', 'Random')
    generators = ('PGF2', )
    egos = ('autopilot', 'BehaviorAgent', 'intersectionAgent', 'TFPP')
    trial_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    coverages = ('traffic-rules', )
    report_max_time = timedelta(hours=24)
    RQ1_folder = f'evaluation/results/RQ1'

    stats = {
        'Valid-Fuzz-Inputs': total_valid_fuzz_inputs,
        'Ego-Violations': total_ego_violations,
        'Predicate-Set-Coverages': total_PredicateSetCoverage,
    }


    # dependent variables
    experiments = tuple(product(generators, egos, coverages))
    CPU_COUNT = len(os.sched_getaffinity(0))
    MAX_JOBS = CPU_COUNT
    MAX_JOBS = 1

    spawn_ctx = multiprocessing.get_context('spawn')
    processes = []

    for experiment in experiments:
        generator, ego, coverage = experiment
        stats_file = f'{RQ1_folder}/{generator}_{ego}_{coverage}/stats.json'

        if SKIP_EXISTING and Path(stats_file).is_file():
            print(f'Skipping existing {stats_file}')
            continue

        report_process = spawn_ctx.Process(target=save_stats,
                                            args=(experiment,
                                                    trial_seeds,
                                                    stats,
                                                    stats_file),
                                            name=f'RQ1_{generator}_{ego}_{coverage}_stats',
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