from itertools import combinations
import copy
import clingo

from scenariogen.core.utils import classify_intersection
from scenariogen.predicates.utils import predicates_of_logic_program, time_to_term, term_to_time
from scenariogen.core.coverages.coverage import Statement, StatementCoverage, StatementSetCoverage, Predicate, PredicateCoverage
from scenariogen.predicates.predicates import geometry_atoms
from scenariogen.predicates.events import ActorSpawnedEvent
from experiments.configs import coverage_config


def coverage_space(config):
  traffic_rules_file = classify_intersection(config['network'], config['intersection']) + '.lp'
  logic_files = (f'src/scenariogen/predicates/{traffic_rules_file}',
                  'src/scenariogen/predicates/traffic.lp',
                )
  encoding = ''
  for file_path in logic_files:
    with open(file_path, 'r') as f:
      encoding += f.read()
  
  predicate_coverage_space = PredicateCoverage(predicates_of_logic_program(encoding))

  return predicate_coverage_space


def to_coverage(events, config):
  events = copy.deepcopy(events)
  config = {**coverage_config, **config}

  traffic_rules_file = classify_intersection(config['network'], config['intersection']) + '.lp'
  logic_files = (f'src/scenariogen/predicates/{traffic_rules_file}',
                  'src/scenariogen/predicates/traffic.lp',
                  'src/scenariogen/predicates/abstractions.lp'
                )
  encoding = ''
  for file_path in logic_files:
    with open(file_path, 'r') as f:
      encoding += f.read()

  ordinal2time = {f't{i}':t for i,t in enumerate(sorted(set(e.time for e in events)))}
  spawn_events = [e for e in events if type(e) is ActorSpawnedEvent]
  lanes = set(e.lane for e in spawn_events)
  lane2spawnEvents = {l: sorted(list(filter(lambda e: e.lane == l, spawn_events)), reverse=True, key=lambda e: e.progress)
                      for l in lanes}
  old2new = {e.vehicle: f'{e.lane}_v{i}'
            for l in lanes
            for i, e in enumerate(lane2spawnEvents[l])}
  old2new['ego'] = 'ego'

  # Choose symbolic constants for event times
  time2ordinal = {t:o for o,t in ordinal2time.items()}
  for e in events:
    e.time = time2ordinal[e.time]

  # Rename nonegos based on their spawn lane and progress relative to other nonegos on the same lane    
  for e in events:
    e.vehicle = old2new[e.vehicle]
    if hasattr(e, 'other') and e.other in old2new:
      e.other = old2new[e.other]


  temporal_order = ['equal(T, T):- eventTime(T)',
                    'equal(T1, T2):- equal(T2, T1)',
                    'lessThan(T1, T3):- lessThan(T1, T2), lessThan(T2, T3)']
  for t1, t2 in combinations(ordinal2time.keys(), 2):
    if abs(ordinal2time[t2] - ordinal2time[t1]) < config['min_perceptible_time']:
      temporal_order.append(f'equal({t1}, {t2})')

  ordinals = tuple(ordinal2time.keys())
  for i, oi in enumerate(ordinals[:-1]):
    ti = ordinal2time[oi]
    for j, oj in enumerate(ordinals[i+1:]):
      tj = ordinal2time[oj]
      if tj - ti < config['min_perceptible_time']:
        continue
      else:
        temporal_order.append(f'lessThan({oi}, {oj})')
        for ok in ordinals[j+1:]:
          tk = ordinal2time[ok]
          if tk - tj < config['min_perceptible_time']:
            # lessThan(oi, oj) and equal(oj, ok) are not enough to imply lessThan(oi, ok),
            # but we know that tj < tk, so we must add:
            temporal_order.append(f'lessThan({oi}, {ok})')
          else:
            # lessThan(oi, oj) and lessThan(oj, ok) imply lessThan(oi, ok)
            break
        break
  
  atoms = []
  atoms += geometry_atoms(config['network'], config['intersection'])
  atoms += [str(e) for e in events]
  atoms += temporal_order
  instance = '.\n'.join(atoms)+'.\n'

  ctl = clingo.Control()
  ctl.add("base", [], encoding+instance)
  ctl.ground([("base", [])])
  ctl.configuration.solve.models = "1"
  
  statements = []
  predicate_coverage_space = coverage_space(config)

  with ctl.solve(yield_=True) as handle:
    for model in handle:
      for atom in model.symbols(atoms=True):
        predicate = Predicate(atom.name)
        if not predicate in predicate_coverage_space:
          continue
        args = tuple(map(str, atom.arguments))
        statements.append(Statement(predicate, args))

  return StatementSetCoverage((StatementCoverage(statements),))