
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

class Coverage:
  coverage: None
 
  def __sub__(self, other):
     return self.coverage - other.coverage
  
  def __iadd__(self, other):
     self.coverage += other.coverage 

  def __len__(self):
    return len(self.coverage)
  
  def is_novel_to(self, other):
     return len(self.coverage.keys() - other.coverage.keys()) == 0

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
  cov = new Coverage,
    with coverage Counter(predicates)
  return cov
  

events = []
scenario EvaluateCoverageScenario():
  setup:
    record final to_coverage(events) as coverage

    monitor record_events():
      cars = simulation().agents
      maneuvers = intersection.maneuvers
      arrived = {car: False for car in cars}
      entered = {car: False for car in cars}
      exited = {car: False for car in cars}
      lanes = {car: set() for car in cars}
      inIntersection = {car: False for car in cars}
      while True:
        currentTime = simulation().currentTime * config['timestep']
        for car in cars:
          inIntersection[car] = car.intersects(intersection)
          
          if (not arrived[car]) and (distance from (front of car) to intersection) < config['arrival_distance']:
            arrived[car] = True
            events.append(ArrivedAtIntersectionEvent(car.name, car.lane.uid, currentTime))
            events.append(SignaledAtForkEvent(car.name, car.lane.uid, car.signal.name.lower(), currentTime))
          if inIntersection[car] and not entered[car]:
            entered[car] = True
            events.append(EnteredIntersectionEvent(car.name, car.lane.uid, currentTime))
          if entered[car] and (not exited[car]) and not inIntersection[car]:
            exited[car] = True
            events.append(ExitedIntersectionEvent(car.name, car.lane.uid, currentTime))

          for maneuver in maneuvers:
            lane = maneuver.connectingLane
            wasOnLane = lane.uid in lanes[car]
            isOnLane = car.intersects(lane)
            if isOnLane and not wasOnLane:
              lanes[car].add(lane.uid)
              events.append(EnteredLaneEvent(car.name, lane.uid, currentTime))
            elif wasOnLane and not isOnLane:
              lanes[car].remove(lane.uid)
              events.append(ExitedLaneEvent(car.name, lane.uid, currentTime))
        wait