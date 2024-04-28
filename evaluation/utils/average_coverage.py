#!/usr/bin/env python3

""" Generate the coverage reports """

import jsonpickle
import numpy as np
import statistics

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


def report(trials, coverage_filter, output_file):
  ts = np.arange(0, trials[0]['max-total-time'], 30)

  fuzz_inputs_num_trials_samples = []
  statementSet_trials_samples = []
  statement_trials_samples = []
  predicateSet_trials_samples = []
  predicate_trials_samples = []

  for test_config in trials:
    trial_samples = sample_trial(test_config, ts, coverage_filter)

    fuzz_inputs_num_trials_samples.append(trial_samples['fuzz-inputs-num'])
    statementSet_trials_samples.append(trial_samples['statementSet'])
    statement_trials_samples.append(trial_samples['statement'])
    predicateSet_trials_samples.append(trial_samples['predicateSet'])
    predicate_trials_samples.append(trial_samples['predicate'])
  
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
