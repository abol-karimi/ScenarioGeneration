
model scenic.domains.driving.model
config = globalParameters.config
intersection = network.elements[config['intersection']]

# python imports
import clingo
from scenariogen.core.utils import classify_intersection
from scenariogen.predicates.predicates import TemporalOrder, geometry_atoms
from scenariogen.predicates.events import *
from scenariogen.core.coverages.coverage import StatementCoverage as Coverage

traffic_rules_file = classify_intersection(network, config['intersection']) + '.lp'
logic_files = (f'src/scenariogen/predicates/{traffic_rules_file}',
                'src/scenariogen/predicates/traffic.lp',
                'src/scenariogen/predicates/abstractions.lp'
              )
encoding = ''
for file_path in logic_files:
  with open(file_path, 'r') as f:
    encoding += f.read()

def to_coverage(events):
  atoms = []
  atoms += geometry_atoms(network,
                          config['intersection'])
  atoms += [str(e) for e in events]
  instance = '.\n'.join(atoms)+'.\n'

  ctl = clingo.Control()
  ctl.add("base", [], encoding+instance)
  ctl.ground([("base", [])], context=TemporalOrder())
  ctl.configuration.solve.models = "1"
  coverage = Coverage([])
  with ctl.solve(yield_=True) as handle:
    for model in handle:
      for atom in model.symbols(atoms=True):
        if atom.name.endswith('AtTime') or \
            atom.name == 'changedSignalBetween':
          continue
        coverage.add(atom.name, tuple(str(arg) for arg in atom.arguments))

  return coverage


from scenariogen.predicates.monitors import (ArrivingAtIntersectionMonitor,
                                             VehicleSignalMonitor,
                                             StoppingMonitor,
                                             RegionOverlapMonitor,
                                             OcclusionMonitor,
                                            )

events = []
trigger_regions = [intersection] + [m.connectingLane for m in intersection.maneuvers]

monitor CoverageMonitor(coverageOut):
  require monitor VehicleSignalMonitor(config, events)
  require monitor ArrivingAtIntersectionMonitor({**config, 'network': network}, events)
  require monitor StoppingMonitor(config, events)
  require monitor RegionOverlapMonitor({**config, 'regions': trigger_regions}, events)
  require monitor OcclusionMonitor(config, events)
  require monitor CollisionMonitor(config, events)

  for step in range(config['steps']):
    wait
  coverageOut.update(to_coverage(events))
  print('Coverage monitor last statement!')
  wait
  print('Should not reach here!')
