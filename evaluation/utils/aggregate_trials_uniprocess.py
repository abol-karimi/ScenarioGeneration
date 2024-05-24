#!/usr/bin/env python3

""" Generate the coverage reports """

import jsonpickle
import numpy as np

from evaluation.utils.utils import sample_trial


def report(results_files, total_seconds, coverage_filter, output_file, period):
    ts = np.arange(0, total_seconds, period)

    fuzz_inputs_trials_samples = []
    statementSet_trials_samples = []
    statement_trials_samples = []
    predicateSet_trials_samples = []
    predicate_trials_samples = []

    for results_file in results_files:
        trial_samples = sample_trial(results_file, ts, coverage_filter)

        fuzz_inputs_trials_samples.append(trial_samples['FuzzInputs'])
        statementSet_trials_samples.append(trial_samples['StatementSets'])
        statement_trials_samples.append(trial_samples['Statements'])
        predicateSet_trials_samples.append(trial_samples['PredicateSets'])
        predicate_trials_samples.append(trial_samples['Predicates'])
    
    result = {
        'elapsed-time': tuple(map(float, ts)),
        'fuzz-inputs': tuple(tuple(s[i] for s in fuzz_inputs_trials_samples) for i in range(len(ts))),
        'statementSets': tuple(tuple(s[i] for s in statementSet_trials_samples) for i in range(len(ts))),
        'statements': tuple(tuple(s[i] for s in statement_trials_samples) for i in range(len(ts))),
        'predicateSets': tuple(tuple(s[i] for s in predicateSet_trials_samples) for i in range(len(ts))),
        'predicates': tuple(tuple(s[i] for s in predicate_trials_samples) for i in range(len(ts))),
    }

    with open(output_file, 'w') as f:
        f.write(jsonpickle.encode(result, indent=1))