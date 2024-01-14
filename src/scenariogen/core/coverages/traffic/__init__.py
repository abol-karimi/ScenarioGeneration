from itertools import chain
import clingo

from scenariogen.core.utils import classify_intersection
from scenariogen.predicates.utils import predicates_of_logic_program, time_to_term, term_to_time
from scenariogen.core.coverages.coverage import StatementCoverage
from scenariogen.predicates.predicates import TemporalOrder, geometry_atoms
from scenariogen.predicates.events import ActorSpawnedEvent


treat_unbounded_parameters = 'ignore'


def coverage_space(config):
  traffic_rules_file = classify_intersection(config['network'], config['intersection']) + '.lp'
  logic_files = (f'src/scenariogen/predicates/{traffic_rules_file}',
                  'src/scenariogen/predicates/traffic.lp',
                )
  encoding = ''
  for file_path in logic_files:
    with open(file_path, 'r') as f:
      encoding += f.read()
  
  predicate_coverage_space = predicates_of_logic_program(encoding)

  return predicate_coverage_space


def to_coverage(events, config):
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

  if treat_unbounded_parameters == 'to_ordinal':
    banned_terms = set()
    to_seconds = lambda x: ordinal2time[x]

    # Choose symbolic constants for event times
    time2ordinal = {t:o for o,t in ordinal2time.items()}
    for e in events:
      e.time = time2ordinal[e.time]

    # Rename nonegos based on their spawn lane and progress relative to other nonegos on the same lane    
    for e in events:
      e.vehicle = old2new[e.vehicle]
      if hasattr(e, 'other'):
        e.other = old2new[e.other]

  elif treat_unbounded_parameters == 'ignore':
    banned_terms = set(chain(ordinal2time.keys(), old2new.keys()))
    to_seconds = lambda x: ordinal2time[x]

    time2ordinal = {t:o for o,t in ordinal2time.items()}
    for e in events:
      e.time = time2ordinal[e.time]

  else:
    banned_terms = set()
    to_seconds = term_to_time

    for e in events:
      e.time = time_to_term(e.time)

  atoms = []
  atoms = geometry_atoms(config['network'], config['intersection']) + atoms
  atoms += [str(e) for e in events]
  instance = '.\n'.join(atoms)+'.\n'

  ctl = clingo.Control()
  ctl.add("base", [], encoding+instance)
  ctl.ground([("base", [])], context=TemporalOrder(to_seconds))
  ctl.configuration.solve.models = "1"
  statement_coverage = StatementCoverage([])

  with ctl.solve(yield_=True) as handle:
    for model in handle:
      for atom in model.symbols(atoms=True):
        args = tuple('_' if arg in banned_terms else arg
                     for arg in map(str, atom.arguments))
        statement_coverage.add(atom.name, args)

  return statement_coverage