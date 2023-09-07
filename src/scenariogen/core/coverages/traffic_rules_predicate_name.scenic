
model scenic.domains.driving.model
config = globalParameters.config
intersection = network.elements[config['intersection']]

# python imports
from collections import Counter
import clingo
from scenic.domains.driving.roads import Network
from scenariogen.core.utils import geometry_atoms
from scenariogen.core.events import *
from scenariogen.predicates.predicates import TemporalOrder

from scenariogen.core.coverages.coverage import Coverage

def to_coverage(events):
  print('Computing predicate-name coverage...')
  atoms = []
  atoms += geometry_atoms(network,
                          config['intersection'])
  atoms += [str(e) for e in events]
  program = '.\n'.join(atoms)+'.\n'

  ctl = clingo.Control()
  ctl.load(f"src/scenariogen/predicates/{config['traffic_rules']}")
  ctl.add("base", [], program)
  ctl.ground([("base", [])], context=TemporalOrder())
  ctl.configuration.solve.models = "1"
  predicates = set()
  with ctl.solve(yield_=True) as handle:
      for model in handle:
          for atom in model.symbols(atoms=True):
              predicates.add(str(atom.name))
  return Coverage(predicates)
  

monitor CoverageMonitor(maxSteps):
  coverage = None
  events = []
  cars = simulation().agents
  maneuvers = intersection.maneuvers
  arrived = {car: False for car in cars}
  entered = {car: False for car in cars}
  exited = {car: False for car in cars}
  lanes = {car: set() for car in cars}
  inIntersection = {car: False for car in cars}
  for step in range(maxSteps):
    time_seconds = step * config['timestep']
    for car in cars:
      inIntersection[car] = car.occupiedSpace.intersects(intersection.footprint)
      
      if (not arrived[car]) and (distance from (front of car) to intersection) < config['arrival_distance']:
        arrived[car] = True
        events.append(ArrivedAtIntersectionEvent(car.name, car.lane.uid, time_seconds))
        events.append(SignaledAtForkEvent(car.name, car.lane.uid, car.signal.name.lower(), time_seconds))
      if inIntersection[car] and not entered[car]:
        entered[car] = True
        events.append(EnteredIntersectionEvent(car.name, car.lane.uid, time_seconds))
      if entered[car] and (not exited[car]) and not inIntersection[car]:
        exited[car] = True
        events.append(ExitedIntersectionEvent(car.name, car.lane.uid, time_seconds))

      for maneuver in maneuvers:
        lane = maneuver.connectingLane
        wasOnLane = lane.uid in lanes[car]
        isOnLane = car.occupiedSpace.intersects(lane.footprint)
        if isOnLane and not wasOnLane:
          lanes[car].add(lane.uid)
          events.append(EnteredLaneEvent(car.name, lane.uid, time_seconds))
        elif wasOnLane and not isOnLane:
          lanes[car].remove(lane.uid)
          events.append(ExitedLaneEvent(car.name, lane.uid, time_seconds))
    wait
  coverage = to_coverage(events)
  print('Monitor last statement!')
  wait