
model scenic.domains.driving.model
config = globalParameters.config
intersection = network.elements[config['intersection']]

# python imports
import clingo
from scenariogen.core.utils import classify_intersection
from scenariogen.predicates.predicates import TemporalOrder, geometry_atoms
from scenariogen.predicates.events import *
from scenariogen.core.coverages.coverage import StatementSetCoverage

traffic_rules_file = classify_intersection(network, config['intersection']) + '.lp'
logic_files = (f'src/scenariogen/predicates/{traffic_rules_file}',
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
  ctl.add("base", [], instance+encoding)
  ctl.ground([("base", [])], context=TemporalOrder())
  ctl.configuration.solve.models = "1"
  coverage = StatementSetCoverage([])
  with ctl.solve(yield_=True) as handle:
    for model in handle:
      for atom in model.symbols(atoms=True):
        coverage.add(atom.name, tuple(str(arg) for arg in atom.arguments))

  return coverage


from scenariogen.predicates.monitors import (ArrivingAtIntersectionMonitor,
                                             VehicleSignalMonitor,
                                             StoppingMonitor,
                                             RegionOverlapMonitor,
                                             OcclusionMonitor,
                                             NewtonianCollisionMonitor,
                                             ActorsMonitor
                                            )

trigger_regions = [intersection] + [m.connectingLane for m in intersection.maneuvers]

monitor EventsMonitor(eventsOut):
  require monitor VehicleSignalMonitor(config, eventsOut)
  require monitor ArrivingAtIntersectionMonitor({**config, 'network': network}, eventsOut)
  require monitor StoppingMonitor(config, eventsOut)
  require monitor RegionOverlapMonitor({**config, 'regions': trigger_regions}, eventsOut)
  require monitor OcclusionMonitor(config, eventsOut)
  require monitor NewtonianCollisionMonitor(config, eventsOut)
  require monitor ActorsMonitor(config, eventsOut)

  while True:
    wait