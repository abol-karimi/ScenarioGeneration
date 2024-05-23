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


def trials_samples_stats(trials_samples, stat):
    samples_num_max = max(len(s) for s in trials_samples)
    stats = []
    for i in range(samples_num_max):
        stats.append(stat(s[i] for s in trials_samples if len(s) > i))
    return tuple(stats)


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

    fuzz_inputs_num_trials_samples.put({results_file: trial_samples['fuzz-inputs-num']})
    statementSet_trials_samples.put({results_file: trial_samples['statementSet']})
    statement_trials_samples.put({results_file: trial_samples['statement']})
    predicateSet_trials_samples.put({results_file: trial_samples['predicateSet']})
    predicate_trials_samples.put({results_file: trial_samples['predicate']})

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
    
    fuzz_inputs_num_trials_samples = {}
    statementSet_trials_samples = {}
    statement_trials_samples = {}
    predicateSet_trials_samples = {}
    predicate_trials_samples = {}
    for _ in results_files:
        fuzz_inputs_num_trials_samples.update(fuzz_inputs_num_trials_samples_queue.get())
        statementSet_trials_samples.update(statementSet_trials_samples_queue.get())
        statement_trials_samples.update(statement_trials_samples_queue.get())
        predicateSet_trials_samples.update(predicateSet_trials_samples_queue.get())
        predicate_trials_samples.update(predicate_trials_samples_queue.get())

    fuzz_inputs_num_trials_samples = [fuzz_inputs_num_trials_samples[f] for f in results_files]
    statementSet_trials_samples = [statementSet_trials_samples[f] for f in results_files]
    statement_trials_samples = [statement_trials_samples[f] for f in results_files]
    predicateSet_trials_samples = [predicateSet_trials_samples[f] for f in results_files]
    predicate_trials_samples = [predicate_trials_samples[f] for f in results_files]


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
        'fuzz-inputs-num_median': trials_samples_stats(fuzz_inputs_num_trials_samples, statistics.median),
        'fuzz-inputs-num_min': trials_samples_stats(fuzz_inputs_num_trials_samples, min),
        'fuzz-inputs-num_max': trials_samples_stats(fuzz_inputs_num_trials_samples, max),
        'statementSet_median': trials_samples_stats(statementSet_trials_samples, statistics.median),
        'statementSet_min': trials_samples_stats(statementSet_trials_samples, min),
        'statementSet_max': trials_samples_stats(statementSet_trials_samples, max),
        'statement_median': trials_samples_stats(statement_trials_samples, statistics.median),
        'statement_min': trials_samples_stats(statement_trials_samples, min),
        'statement_max': trials_samples_stats(statement_trials_samples, max),
        'predicateSet_median': trials_samples_stats(predicateSet_trials_samples, statistics.median),
        'predicateSet_min': trials_samples_stats(predicateSet_trials_samples, min),
        'predicateSet_max': trials_samples_stats(predicateSet_trials_samples, max),
        'predicate_median': trials_samples_stats(predicate_trials_samples, statistics.median),
        'predicate_min': trials_samples_stats(predicate_trials_samples, min),
        'predicate_max': trials_samples_stats(predicate_trials_samples, max),
    }

    with open(output_file, 'w') as f:
        f.write(jsonpickle.encode(result, indent=1))
