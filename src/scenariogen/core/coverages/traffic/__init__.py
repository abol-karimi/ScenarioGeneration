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

  event_times = sorted(set(e.time for e in events))
  ordinals = tuple(f't{i}' for i in range(len(event_times)))
  ordinal2time = {o:t for o,t in zip(ordinals, event_times)}
  time2ordinal = {t:o for o,t in zip(ordinals, event_times)}

  spawn_events = [e for e in events if type(e) is ActorSpawnedEvent]
  lanes = set(e.lane for e in spawn_events)
  lane2spawnEvents = {l: sorted(list(filter(lambda e: e.lane == l, spawn_events)), reverse=True, key=lambda e: e.progress)
                      for l in lanes}
  old2new = {e.vehicle: f'{e.lane}_v{i}'
            for l in lanes
            for i, e in enumerate(lane2spawnEvents[l])}
  old2new['ego'] = 'ego'

  # Choose symbolic constants for event times
  for e in events:
    e.time = time2ordinal[e.time]

  # Rename nonegos based on their spawn lane and progress relative to other nonegos on the same lane    
  for e in events:
    e.vehicle = old2new[e.vehicle]
    if hasattr(e, 'other') and e.other in old2new:
      e.other = old2new[e.other]


  # To reduce the logic program size,
  # we try to encode the perceptible temporal order between the events as compactly as possible
  temporal_order = ['equal(T, T):- eventTime(T)',
                    'equal(T1, T2):- equal(T2, T1)',
                    'lessThan(T1, T3):- lessThan(T1, T2), lessThan(T2, T3)']
  for o1, o2 in combinations(ordinals, 2):
    if abs(ordinal2time[o2] - ordinal2time[o1]) < config['min_perceptible_time']:
      temporal_order.append(f'equal({o1}, {o2})')

  for i in range(len(event_times)-1):
    ti = event_times[i]
    for j in range(i+1, len(event_times)):
      tj = event_times[j]
      if tj - ti < config['min_perceptible_time']:
        continue
      else:
        temporal_order.append(f'lessThan({ordinals[i]}, {ordinals[j]})')
        for k in range(j+1, len(event_times)):
          tk = event_times[k]
          if tk - tj < config['min_perceptible_time']:
            # lessThan(oi, oj) and equal(oj, ok) are not enough to imply lessThan(oi, ok),
            # but we know that tj < tk, so we must add:
            temporal_order.append(f'lessThan({ordinals[i]}, {ordinals[k]})')
          else:
            # lessThan(oi, oj) and lessThan(oj, ok) imply lessThan(oi, ok) so no need to add it explicitly
            break
        break
  for o in temporal_order:
    print(o)
  
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