from pathlib import Path
from more_itertools import pairwise
import sympy
import jsonpickle
import numpy as np
from functools import reduce

from scenariogen.core.fuzzing.fuzzers.seed_tester import SeedTester
from scenariogen.core.coverages.coverage import StatementSetCoverage, StatementCoverage, PredicateSetCoverage, PredicateCoverage
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
    'coverages-folder': f'{output_folder}/coverages',
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
  results_file_path = Path(test_config['results-file'])

  print(f'Loading {results_file_path} ...')
  with open(results_file_path, 'r') as f:
    results = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']}, results)['measurements']
  elapsed_times = tuple(m['elapsed-time'] for m in measurements)

  fuzz_input_files = [m['new-fuzz-input-files'] for m in measurements]

  statementSet_coverages = []
  for m in measurements:
    new_statement_coverages = []
    for coverage_file in m['new-coverage-files']:
      with open(coverage_file, 'r') as f:
        statement_coverage = coverage_filter(jsonpickle.decode(f.read()))
        new_statement_coverages.append(statement_coverage)
    statementSet_coverages.append(StatementSetCoverage(new_statement_coverages))

  predicateSet_coverages = tuple(c.cast_to(PredicateSetCoverage) for c in statementSet_coverages)
  statement_coverages = tuple(c.cast_to(StatementCoverage) for c in statementSet_coverages)
  predicate_coverages = tuple(c.cast_to(PredicateCoverage) for c in statement_coverages)

  fuzz_input_files_acc = [fuzz_input_files[0]]
  statementSet_acc = [statementSet_coverages[0]]
  predicateSet_acc = [predicateSet_coverages[0]]
  statement_acc = [statement_coverages[0]]
  predicate_acc = [predicate_coverages[0]]
  for i in range(1, len(measurements)):
    fuzz_input_files_acc.append(fuzz_input_files_acc[-1].union(fuzz_input_files[i]))
    statementSet_acc.append(statementSet_acc[-1] + statementSet_coverages[i])
    predicateSet_acc.append(predicateSet_acc[-1] + predicateSet_coverages[i])
    statement_acc.append(statement_acc[-1] + statement_coverages[i])
    predicate_acc.append(predicate_acc[-1] + predicate_coverages[i])
  
  interpolate = piecewise_constant_numpy
  interpolator = interpolate.__name__

  print(f'Sampling trial using interpolator {interpolator}...')
  fuzz_inputs_num_samples = interpolate(ts, elapsed_times, tuple(len(c) for c in fuzz_input_files_acc))
  statementSet_samples = interpolate(ts, elapsed_times, tuple(len(c) for c in statementSet_acc))
  statement_samples = interpolate(ts, elapsed_times, tuple(len(c) for c in statement_acc))
  predicateSet_samples = interpolate(ts, elapsed_times, tuple(len(c) for c in predicateSet_acc))
  predicate_samples = interpolate(ts, elapsed_times, tuple(len(c) for c in predicate_acc))

  return {'fuzz-inputs-num': fuzz_inputs_num_samples,
          'statementSet': statementSet_samples,
          'statement': statement_samples,
          'predicateSet': predicateSet_samples,
          'predicate': predicate_samples}