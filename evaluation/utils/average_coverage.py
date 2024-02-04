#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from more_itertools import pairwise
import numpy as np
import sympy
from functools import reduce
import statistics

from scenariogen.core.coverages.coverage import StatementCoverage, PredicateSetCoverage, PredicateCoverage


def piecewise_linear_sympy(ts, xs, ys):
  x = sympy.Symbol('x', real=True)
  pieces = [
    (((x-a)*fb+(b-x)*fa)/(b-a),
     (x >= a) & (x < b)
     ) for (a,b),(fa,fb) in zip(pairwise(xs), pairwise(ys))
  ] + [(ys[-1], x >= xs[-1])]
  x2y = sympy.Piecewise(*pieces)
  return tuple(x2y.subs(x, t) for t in ts)


def piecewise_constant_sympy(ts, xs, ys):
  print(f'Interpolation refs: {list(zip(xs,ys))}')
  print(f'Interpolation evals: {ts}')
  x = sympy.Symbol('x', real=True)
  pieces = [(fa, (x >= a) & (x < b))
            for (a,b),(fa,fb) in zip(pairwise(xs), pairwise(ys))
            ] + [(ys[-1], x >= xs[-1])]
  x2y = sympy.Piecewise(*pieces)
  return tuple(x2y.subs(x, t) for t in ts)


def piecewise_constant_numpy(ts, xs, ys):
  condlist = [(ts >= a) & (ts < b)
              for (a,b) in pairwise(xs)
              ] + [ts >= xs[-1]]
  funclist = [fa for (fa,fb) in pairwise(ys)
              ] + [ys[-1]]
  
  arr = np.piecewise(ts, condlist, funclist)
  return tuple(map(float, arr))


def sample_trial(test_config, ts):
  coverage_file_path = Path(test_config['output-folder'])/'coverage.json'

  print(f'Loading {coverage_file_path} ...')
  with open(coverage_file_path, 'r') as f:
    coverage = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                          coverage)['measurements']
  elapsed_times = tuple(m['elapsed_time'] for m in measurements)
  statementSet_coverages = tuple(m['statement-set-coverage'] for m in measurements)

  statementSet_acc = [statementSet_coverages[0]]
  for i in range(1, len(measurements)):
    statementSet_acc.append(statementSet_acc[-1] + statementSet_coverages[i])
  
  print(f'Down-casting statement-set coverages to statement coverages...')
  statement_acc = tuple(c.cast_to(StatementCoverage) for c in statementSet_acc)
  
  print(f'Down-casting statement-set coverages to predicate-set coverages...')
  predicateSet_acc = tuple(c.cast_to(PredicateSetCoverage) for c in statementSet_acc)

  print(f'Down-casting statement coverages to predicate coverages...')
  predicate_acc = tuple(c.cast_to(PredicateCoverage) for c in statement_acc)

  interpolator = piecewise_constant_numpy

  print(f'Evaluating statement-set coverages using {interpolator.__name__}...')
  statementSet_samples = interpolator(ts, elapsed_times, tuple(len(c) for c in statementSet_acc))

  print(f'Evaluating statement coverages using {interpolator.__name__}...')
  statement_samples = interpolator(ts, elapsed_times, tuple(len(c) for c in statement_acc))

  print(f'Evaluating predicate-set coverages using {interpolator.__name__}...')
  predicateSet_samples = interpolator(ts, elapsed_times, tuple(len(c) for c in predicateSet_acc))
  
  print(f'Evaluating predicate coverages using {interpolator.__name__}...')
  predicate_samples = interpolator(ts, elapsed_times, tuple(len(c) for c in predicate_acc))

  return (statementSet_samples,
          statement_samples,
          predicateSet_samples,
          predicate_samples)


def report(trials, output_file):
  ts = np.arange(0, trials[0][1]['max-total-time'], 30)

  statementSet_trials_samples = []
  statement_trials_samples = []
  predicateSet_trials_samples = []
  predicate_trials_samples = []

  for _, test_config in trials:
    trial_samples = sample_trial(test_config, ts)

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
