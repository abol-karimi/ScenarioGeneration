
model scenic.domains.driving.model
config = globalParameters.config
intersection = network.elements[config['intersection']]

# python imports
from collections import Counter
import clingo
from clingo.ast import Transformer, parse_string
from scenic.domains.driving.roads import Network
from scenariogen.core.utils import geometry_atoms
from scenariogen.core.events import *
from scenariogen.predicates.predicates import TemporalOrder

with open(f"src/scenariogen/predicates/{config['traffic_rules']}", 'r') as f:
  encoding = f.read()

coverage_space = set()
class AtomNameRecorder(Transformer):
  def visit_SymbolicAtom(self, node):
    coverage_space.add(node.symbol.name)
    return node
anr = AtomNameRecorder()
parse_string(encoding, lambda stm: anr(stm))

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
  coverage = set()
  with ctl.solve(yield_=True) as handle:
      for model in handle:
          for atom in model.symbols(atoms=True):
              coverage.add(str(atom.name))
  return coverage

coverage = set()
monitor CoverageMonitor():
  events = []
  cars = simulation().agents
  maneuvers = intersection.maneuvers
  arrived = {car: False for car in cars}
  entered = {car: False for car in cars}
  exited = {car: False for car in cars}
  lanes = {car: set() for car in cars}
  inIntersection = {car: False for car in cars}
  for step in range(config['steps']):
    time_seconds = step * config['timestep']
    for car in cars:
      inIntersection[car] = intersection.intersects(PolygonalRegion(polygon=car._boundingPolygon))
      
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
        isOnLane = lane.intersects(PolygonalRegion(polygon=car._boundingPolygon))
        if isOnLane and not wasOnLane:
          lanes[car].add(lane.uid)
          events.append(EnteredLaneEvent(car.name, lane.uid, time_seconds))
        elif wasOnLane and not isOnLane:
          lanes[car].remove(lane.uid)
          events.append(ExitedLaneEvent(car.name, lane.uid, time_seconds))
    wait
  coverage.update(to_coverage(events))
  print('Coverage monitor last statement!')
  wait
  print('Should not reach here!')
