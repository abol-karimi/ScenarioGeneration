from pathlib import Path
from more_itertools import pairwise
import sympy
import jsonpickle
import numpy as np
from functools import reduce

from scenariogen.core.fuzzing.fuzzers.seed_tester import SeedTester
from scenariogen.core.coverages.coverage import Predicate, StatementCoverage, PredicateSetCoverage, PredicateCoverage
from evaluation.configs import SUT_config, coverage_config


def get_test_config(gen_config, test_ego, test_coverage, max_total_time):
  if test_ego in {'TFPP', 'autopilot'}:
    simulator = 'carla'
  elif test_ego in {'intersectionAgent'}:
    simulator = 'newtonian'
  else:
    raise ValueError(f'Are you sure you want to include agent {test_ego} in the experiments?')
  
  output_folder = f"{gen_config['output-folder']}/{test_ego}_{test_coverage}"

  config = {
    'generator': SeedTester,
    'output-folder': output_folder,
    'results-file': f'{output_folder}/results.json',
    'seeds-folder': gen_config['fuzz-inputs-folder'],
    'fuzz-inputs-folder': f'{output_folder}/fuzz-inputs',
    'events-folder': f'{output_folder}/events',
    'bugs-folder': f'{output_folder}/bugs',
    'SUT-config': {**SUT_config,
                  'ego-module': f'evaluation.agents.{test_ego}' if test_ego else None,
                  'simulator': simulator,
                  },
    'coverage-config': {**coverage_config,
                        'coverage-module': test_coverage,
                        },
    'max-total-time': max_total_time,
  }

  return config


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

def sample_trial(test_config, ts, coverage_filter):
  coverage_file_path = Path(test_config['output-folder'])/'coverage.json'

  print(f'Loading {coverage_file_path} ...')
  with open(coverage_file_path, 'r') as f:
    coverage = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                          coverage)['measurements']
  elapsed_times = tuple(m['elapsed_time'] for m in measurements)

  statementSet_coverages = tuple(m['statement-set-coverage'] for m in measurements)
  statementSet_coverages = tuple(m['statement-set-coverage'].filter(coverage_filter) for m in measurements)

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