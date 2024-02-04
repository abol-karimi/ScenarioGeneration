#!/usr/bin/env python3.8

""" Generate the coverage reports """

import jsonpickle
import numpy as np
from functools import reduce
import statistics

from evaluation.utils.utils import sample_trial


def report(trials, output_file):
  ts = np.arange(0, trials[0][1]['max-total-time'], 30)

  statementSet_trials_samples = []
  statement_trials_samples = []
  predicateSet_trials_samples = []
  predicate_trials_samples = []

  for _, test_config in trials:
    trial_samples = sample_trial(test_config, ts, lambda s: s)

    statementSet_trials_samples.append(tuple(trial_samples[0]))
    statement_trials_samples.append(tuple(trial_samples[1]))
    predicateSet_trials_samples.append(tuple(trial_samples[2]))
    predicate_trials_samples.append(tuple(trial_samples[3]))
  
  result = {
    'elapsed-time': tuple(map(float, ts)),
    'statementSet_median': tuple(statistics.median([statementSet_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'statementSet_min': tuple(min([statementSet_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'statementSet_max': tuple(max([statementSet_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'statement_median': tuple(statistics.median([statement_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'statement_min': tuple(min([statement_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'statement_max': tuple(max([statement_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'predicateSet_median': tuple(statistics.median([predicateSet_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'predicateSet_min': tuple(min([predicateSet_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'predicateSet_max': tuple(max([predicateSet_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'predicate_median': tuple(statistics.median([predicate_trials_samples[i][j] for i in range(len(trials))]) for j in range(len(ts))),
    'predicate_min': tuple(min([predicate_trials_samples[i][j] for i in range(len(trials))] ) for j in range(len(ts))),
    'predicate_max': tuple(max([predicate_trials_samples[i][j] for i in range(len(trials))] ) for j in range(len(ts))),
  }

  with open(output_file, 'w') as f:
    f.write(jsonpickle.encode(result, indent=1))
