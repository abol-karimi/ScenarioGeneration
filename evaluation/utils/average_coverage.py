#!/usr/bin/env python3

""" Generate the coverage reports """

import jsonpickle
import numpy as np
import statistics
import setproctitle
import multiprocessing
import time
import traceback

from evaluation.utils.utils import sample_trial


def trials_samples_median(trials_samples):
    trials_num = len(trials_samples)
    samples_num = len(trials_samples[0])
    return tuple(statistics.median([trials_samples[i][j] for i in range(trials_num)]) for j in range(samples_num))


def trials_samples_min(trials_samples):
    trials_num = len(trials_samples)
    samples_num = len(trials_samples[0])
    return tuple(min([trials_samples[i][j] for i in range(trials_num)]) for j in range(samples_num))


def trials_samples_max(trials_samples):
    trials_num = len(trials_samples)
    samples_num = len(trials_samples[0])
    return tuple(max([trials_samples[i][j] for i in range(trials_num)]) for j in range(samples_num))


def sample_trial_process(results_file,
                        ts,
                        coverage_filter,
                        fuzz_inputs_num_trials_samples,
                        statementSet_trials_samples,
                        statement_trials_samples,
                        predicateSet_trials_samples,
                        predicate_trials_samples):
    setproctitle.setproctitle(results_file)

    try:
        trial_samples = sample_trial(results_file, ts, coverage_filter)
    except Exception:
        print(f'Exception when sampling {results_file}')
        traceback.print_exc()
        exit(1)
    else:
        print(f'Finished sampling {results_file}')

    fuzz_inputs_num_trials_samples.put(trial_samples['fuzz-inputs-num'])
    statementSet_trials_samples.put(trial_samples['statementSet'])
    statement_trials_samples.put(trial_samples['statement'])
    predicateSet_trials_samples.put(trial_samples['predicateSet'])
    predicate_trials_samples.put(trial_samples['predicate'])

    fuzz_inputs_num_trials_samples.close()
    statementSet_trials_samples.close()
    statement_trials_samples.close()
    predicateSet_trials_samples.close()
    predicate_trials_samples.close()


def report(results_files, total_seconds, coverage_filter, output_file, period):
    setproctitle.setproctitle(output_file)

    ts = np.arange(0, total_seconds, period)

    fuzz_inputs_num_trials_samples_queue = multiprocessing.Queue()
    statementSet_trials_samples_queue = multiprocessing.Queue()
    statement_trials_samples_queue = multiprocessing.Queue()
    predicateSet_trials_samples_queue = multiprocessing.Queue()
    predicate_trials_samples_queue = multiprocessing.Queue()

    processes = []

    for results_file in results_files:
        sampler_process = multiprocessing.Process(target=sample_trial_process,
                                                    args=(results_file,
                                                        ts, 
                                                        coverage_filter,
                                                        fuzz_inputs_num_trials_samples_queue,
                                                        statementSet_trials_samples_queue,
                                                        statement_trials_samples_queue,
                                                        predicateSet_trials_samples_queue,
                                                        predicate_trials_samples_queue
                                                        ),
                                                    name=f'{results_file}'
                                                    )
        sampler_process.start()
        processes.append(sampler_process)
    
    time.sleep(10)
    while True:
        if any(not p.exitcode in {None, 0} for p in processes):
            for p in processes:
                p.kill()
            return
        elif all(p.exitcode == 0 for p in processes):
            break
        else:
            time.sleep(10)
    
    trials_num = len(results_files)
    fuzz_inputs_num_trials_samples = [fuzz_inputs_num_trials_samples_queue.get() for _ in range(trials_num)]
    statementSet_trials_samples = [statementSet_trials_samples_queue.get() for _ in range(trials_num)]
    statement_trials_samples = [statement_trials_samples_queue.get() for _ in range(trials_num)]
    predicateSet_trials_samples = [predicateSet_trials_samples_queue.get() for _ in range(trials_num)]
    predicate_trials_samples = [predicate_trials_samples_queue.get() for _ in range(trials_num)]

    # We average the trials up to the time of the shortest trial
    sample_size = min(len(trial_samples) for trial_samples in fuzz_inputs_num_trials_samples)
    ts = ts[:sample_size]
    fuzz_inputs_num_trials_samples = [samples[:sample_size] for samples in fuzz_inputs_num_trials_samples]
    statementSet_trials_samples = [samples[:sample_size] for samples in statementSet_trials_samples]
    statement_trials_samples = [samples[:sample_size] for samples in statement_trials_samples]
    predicateSet_trials_samples = [samples[:sample_size] for samples in predicateSet_trials_samples]
    predicate_trials_samples = [samples[:sample_size] for samples in predicate_trials_samples]

    result = {
        'elapsed-time': tuple(map(float, ts)),
        'fuzz-inputs-num_median': trials_samples_median(fuzz_inputs_num_trials_samples),
        'fuzz-inputs-num_min': trials_samples_min(fuzz_inputs_num_trials_samples),
        'fuzz-inputs-num_max': trials_samples_max(fuzz_inputs_num_trials_samples),
        'statementSet_median': trials_samples_median(statementSet_trials_samples),
        'statementSet_min': trials_samples_min(statementSet_trials_samples),
        'statementSet_max': trials_samples_max(statementSet_trials_samples),
        'statement_median': trials_samples_median(statement_trials_samples),
        'statement_min': trials_samples_min(statement_trials_samples),
        'statement_max': trials_samples_max(statement_trials_samples),
        'predicateSet_median': trials_samples_median(predicateSet_trials_samples),
        'predicateSet_min': trials_samples_min(predicateSet_trials_samples),
        'predicateSet_max': trials_samples_max(predicateSet_trials_samples),
        'predicate_median': trials_samples_median(predicate_trials_samples),
        'predicate_min': trials_samples_min(predicate_trials_samples),
        'predicate_max': trials_samples_max(predicate_trials_samples),
    }

    with open(output_file, 'w') as f:
        f.write(jsonpickle.encode(result, indent=1))
