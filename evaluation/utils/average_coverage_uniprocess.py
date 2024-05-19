#!/usr/bin/env python3

""" Generate the coverage reports """

import jsonpickle
import numpy as np
import statistics
import time

from evaluation.utils.utils import sample_trial


def trials_samples_stats(trials_samples):
    trials_num = len(trials_samples)
    samples_num = len(trials_samples[0])
    return tuple(statistics.median([trials_samples[i][j] for i in range(trials_num)]) for j in range(samples_num))


def trials_samples_stats(trials_samples):
    trials_num = len(trials_samples)
    samples_num = len(trials_samples[0])
    return tuple(min([trials_samples[i][j] for i in range(trials_num)]) for j in range(samples_num))


def trials_samples_stats(trials_samples):
    trials_num = len(trials_samples)
    samples_num = len(trials_samples[0])
    return tuple(max([trials_samples[i][j] for i in range(trials_num)]) for j in range(samples_num))


def report(results_files, total_seconds, coverage_filter, output_file, period):
    ts = np.arange(0, total_seconds, period)

    fuzz_inputs_num_trials_samples = []
    statementSet_trials_samples = []
    statement_trials_samples = []
    predicateSet_trials_samples = []
    predicate_trials_samples = []

    for results_file in results_files:
        trial_samples = sample_trial(results_file, ts, coverage_filter)

        fuzz_inputs_num_trials_samples.append(trial_samples['fuzz-inputs-num'])
        statementSet_trials_samples.append(trial_samples['statementSet'])
        statement_trials_samples.append(trial_samples['statement'])
        predicateSet_trials_samples.append(trial_samples['predicateSet'])
        predicate_trials_samples.append(trial_samples['predicate'])
    
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