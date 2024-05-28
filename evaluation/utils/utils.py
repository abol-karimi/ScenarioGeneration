from pathlib import Path
from more_itertools import pairwise
import sympy
import jsonpickle
import numpy as np
from functools import reduce
import multiprocessing

from scenariogen.core.fuzzing.fuzzers.seed_tester import SeedTester
from scenariogen.core.coverages.coverage import StatementSetCoverage, StatementCoverage, PredicateSetCoverage, PredicateCoverage
from evaluation.configs import SUT_config, coverage_config


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


def to_StatementSetCoverage(coverage_files, coverage_filter):
    items = []
    for coverage_file in coverage_files:
        with open(coverage_file, 'r') as f:
            items.append(coverage_filter(jsonpickle.decode(f.read())))
    return StatementSetCoverage(items)


def sample_trial(results_file, ts, coverage_filter):
    results_file_path = Path(results_file)

    print(f'Loading {results_file_path} ...')
    with open(results_file_path, 'r') as f:
        results = jsonpickle.decode(f.read())
    print(f'Finished loading {results_file_path}.')

    # Consolidate multi-stage experiments' measurements 
    # (as of now I'm using single-stage experiments due to the overhead of resuming from a previous experiment,
    # but I'm keeping the multi-stage results format in case needed in the future)
    measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']}, results)['measurements']

    samples_fuzz_inputs = []
    samples_StatementSetCoverages = []
    samples_StatementCoverages = []
    samples_PredicateSetCoverages = []
    samples_PredicateCoverages = []
    measurement_idx = 0
    sum_fuzz_inputs = set()
    sum_StatementSetCoverage = StatementSetCoverage([])
    sum_PredicateSetCoverage = PredicateSetCoverage([])
    sum_StatementCoverage = StatementCoverage([])
    sum_PredicateCoverage = PredicateCoverage([])
    for t_sample in ts:
        # Sum all the measurements up to the time of the next sample
        while measurement_idx < len(measurements) and measurements[measurement_idx]['elapsed-time'] <= t_sample:
            sum_fuzz_inputs.update(measurements[measurement_idx]['new-fuzz-input-files'])
            new_StatementSetCoverage = to_StatementSetCoverage(measurements[measurement_idx]['new-coverage-files'], coverage_filter)
            new_PredicateSetCoverage = new_StatementSetCoverage.cast_to(PredicateSetCoverage)
            new_StatementCoverage = new_StatementSetCoverage.cast_to(StatementCoverage)
            new_PredicateCoverage = new_StatementCoverage.cast_to(PredicateCoverage)
            sum_StatementSetCoverage = sum_StatementSetCoverage + new_StatementSetCoverage
            sum_PredicateSetCoverage = sum_PredicateSetCoverage + new_PredicateSetCoverage
            sum_StatementCoverage = sum_StatementCoverage + new_StatementCoverage
            sum_PredicateCoverage = sum_PredicateCoverage + new_PredicateCoverage
            measurement_idx += 1
        
        if measurement_idx == len(measurements) and measurements[measurement_idx-1]['elapsed-time'] < t_sample:
            print(f'{multiprocessing.current_process().name}: Not enough measurements to sample at time {t_sample}.')
            break
    
        # Record the sum as the sample
        samples_fuzz_inputs.append(len(sum_fuzz_inputs))
        samples_StatementSetCoverages.append(len(sum_StatementSetCoverage))
        samples_PredicateSetCoverages.append(len(sum_PredicateSetCoverage))
        samples_StatementCoverages.append(len(sum_StatementCoverage))
        samples_PredicateCoverages.append(len(sum_PredicateCoverage))
    
    return {'FuzzInputs': samples_fuzz_inputs,
            'StatementSets': samples_StatementSetCoverages,
            'PredicateSets': samples_PredicateSetCoverages,
            'Statements': samples_StatementCoverages,
            'Predicates': samples_PredicateCoverages}
