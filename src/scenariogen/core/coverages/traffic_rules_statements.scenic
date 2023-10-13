
model scenic.domains.driving.model
config = globalParameters.config
intersection = network.elements[config['intersection']]

# python imports
import clingo
from scenic.domains.driving.roads import Network
from scenariogen.core.utils import classify_intersection
from scenariogen.predicates.predicates import TemporalOrder, geometry_atoms
from scenariogen.predicates.events import *
from scenariogen.simulators.carla.utils import vehicleLightState_to_signal # TODO bring signal to driving domain
from scenariogen.core.coverages.coverage import StatementCoverage as Coverage

traffic_rules_file = classify_intersection(network, config['intersection']) + '.lp'
with open(f"src/scenariogen/predicates/{traffic_rules_file}", 'r') as f:
  encoding = f.read()

def to_coverage(events):
  print('Computing predicate-name coverage...')
  atoms = []
  atoms += geometry_atoms(network,
                          config['intersection'])
  atoms += [str(e) for e in events]
  instance = '.\n'.join(atoms)+'.\n'
 
  ctl = clingo.Control()
  ctl.add("base", [], instance+encoding)
  ctl.ground([("base", [])], context=TemporalOrder())
  ctl.configuration.solve.models = "1"
  coverage = Coverage([])
  with ctl.solve(yield_=True) as handle:
    for model in handle:
      for atom in model.symbols(atoms=True):
        coverage.add(atom.name, tuple(str(arg) for arg in atom.arguments))

  return coverage


from scenariogen.predicates.monitors import (ArrivingAtIntersectionMonitor,
                                             VehicleSignalMonitor,
                                             StoppingMonitor,
                                             RegionOverlapMonitor)

events = []
trigger_regions = [intersection] + [m.connectingLane for m in intersection.maneuvers]

monitor CoverageMonitor(coverageOut):
  require monitor VehicleSignalMonitor(config, events)
  require monitor ArrivingAtIntersectionMonitor({**config, 'network': network}, events)
  require monitor StoppingMonitor(config, events)
  require monitor RegionOverlapMonitor({**config, 'regions': trigger_regions}, events)

  for step in range(config['steps']):
    wait
  coverageOut.update(to_coverage(events))
  print('Coverage monitor last statement!')
  wait
  print('Should not reach here!')
