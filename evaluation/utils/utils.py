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
  if test_ego in {'TFPP', 'autopilot', 'BehaviorAgent', 'BehaviorAgentRSS'}:
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


def measure_new_StatementSetCoverage(measurement, coverage_filter):
  new_StatementSetCoverage_items = []
  for coverage_file in measurement['new-coverage-files']:
    with open(coverage_file, 'r') as f:
      new_StatementSetCoverage_items.append(coverage_filter(jsonpickle.decode(f.read())))
  return StatementSetCoverage(new_StatementSetCoverage_items)


def sample_trial(results_file, ts, coverage_filter, interpolate=piecewise_constant_numpy):
  results_file_path = Path(results_file)

  print(f'Loading {results_file_path} ...')
  with open(results_file_path, 'r') as f:
    results = jsonpickle.decode(f.read())
  print(f'Finished loading {results_file_path}.')

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']}, results)['measurements']
  elapsed_times = tuple(m['elapsed-time'] for m in measurements)

  # Total number of generated test-cases as a function of time
  fuzz_input_files = [m['new-fuzz-input-files'] for m in measurements]
  fuzz_input_files_acc = [fuzz_input_files[0]]
  for i in range(1, len(measurements)):
    fuzz_input_files_acc.append(fuzz_input_files_acc[-1].union(fuzz_input_files[i]))
  fuzz_inputs_num_samples = interpolate(ts, elapsed_times, tuple(len(c) for c in fuzz_input_files_acc))


  samples_StatementSetCoverage = []
  samples_StatementCoverage = []
  samples_PredicateSetCoverage = []
  samples_PredicateCoverage = []
  next_sample_idx = 0
  sum_StatementSetCoverage = StatementSetCoverage([])
  sum_PredicateSetCoverage = PredicateSetCoverage([])
  sum_StatementCoverage = StatementCoverage([])
  sum_PredicateCoverage = PredicateCoverage([])
  for m in measurements:
    t_measured = m['elapsed-time']
    if t_measured < ts[next_sample_idx]:
      new_StatementSetCoverage = measure_new_StatementSetCoverage(m, coverage_filter)
      new_PredicateSetCoverage = new_StatementSetCoverage.cast_to(PredicateSetCoverage)
      new_StatementCoverage = new_StatementSetCoverage.cast_to(StatementCoverage)
      new_PredicateCoverage = new_StatementCoverage.cast_to(PredicateCoverage)
      sum_StatementSetCoverage = sum_StatementSetCoverage + new_StatementSetCoverage
      sum_PredicateSetCoverage = sum_PredicateSetCoverage + new_PredicateSetCoverage
      sum_StatementCoverage = sum_StatementCoverage + new_StatementCoverage
      sum_PredicateCoverage = sum_PredicateCoverage + new_PredicateCoverage
      continue
    
    while next_sample_idx < len(ts) and ts[next_sample_idx] <= t_measured:
      samples_StatementSetCoverage.append(len(sum_StatementSetCoverage))
      samples_PredicateSetCoverage.append(len(sum_PredicateSetCoverage))
      samples_StatementCoverage.append(len(sum_StatementCoverage))
      samples_PredicateCoverage.append(len(sum_PredicateCoverage))
      next_sample_idx += 1
    
    if next_sample_idx >= len(ts):
      break

  return {'fuzz-inputs-num': fuzz_inputs_num_samples,
          'statementSet': samples_StatementSetCoverage,
          'predicateSet': samples_PredicateSetCoverage,
          'statement': samples_StatementCoverage,
          'predicate': samples_PredicateCoverage}