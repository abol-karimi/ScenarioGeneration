import clingo
from scenic.domains.driving.roads import Network

from scenariogen.core.utils import classify_intersection
from scenariogen.predicates.utils import predicates_of_logic_program
from scenariogen.core.coverages.coverage import StatementCoverage
from scenariogen.predicates.predicates import TemporalOrder, geometry_atoms
from scenariogen.predicates.events import ActorSpawnedEvent

def coverage_space(config):
  network = Network.fromFile(config['map'])
  traffic_rules_file = classify_intersection(network, config['intersection']) + '.lp' 
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
  events = [e.simplified() for e in events]
  
  network = Network.fromFile(config['map'])
  traffic_rules_file = classify_intersection(network, config['intersection']) + '.lp'
  logic_files = (f'src/scenariogen/predicates/{traffic_rules_file}',
                  'src/scenariogen/predicates/traffic.lp',
                  'src/scenariogen/predicates/abstractions.lp'
                )
  encoding = ''
  for file_path in logic_files:
    with open(file_path, 'r') as f:
      encoding += f.read()

  # Choose symbolic constants for event times
  ordinal2time = {f't{i}':t for i,t in enumerate(sorted(set(e.time for e in events)))}
  time2ordinal = {t:o for o,t in ordinal2time.items()}
  for e in events:
    e.time = time2ordinal[e.time]
  
  # Rename nonegos based on their spawn lane and progress relative to other nonegos on the same lane
  spawn_events = [e for e in events if type(e) is ActorSpawnedEvent]
  lanes = set(e.lane for e in spawn_events)
  lane2es = {l: sorted(list(filter(lambda e: e.lane == l, spawn_events)), reverse=True, key=lambda e: e.progress)
             for l in lanes}
  old2new = {e.vehicle: f'{e.lane}_v{i}'
             for l in lanes
             for i, e in enumerate(lane2es[l])}
  old2new['ego'] = 'ego'
  for e in events:
    e.vehicle = old2new[e.vehicle]
    if hasattr(e, 'other'):
      e.other = old2new[e.other]

  atoms = []
  atoms = geometry_atoms(network, config['intersection']) + atoms
  atoms += [repr(e) for e in events]
  instance = '.\n'.join(atoms)+'.\n'

  ctl = clingo.Control()
  ctl.add("base", [], encoding+instance)
  ctl.ground([("base", [])], context=TemporalOrder(ordinal2time))
  ctl.configuration.solve.models = "1"
  coverage = StatementCoverage([])
  with ctl.solve(yield_=True) as handle:
    for model in handle:
      for atom in model.symbols(atoms=True):
        coverage.add(atom.name, tuple(str(arg) for arg in atom.arguments))

  return coverage