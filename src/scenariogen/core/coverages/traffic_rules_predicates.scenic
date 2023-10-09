
model scenic.domains.driving.model
config = globalParameters.config
intersection = network.elements[config['intersection']]

# python imports
from collections import Counter
import clingo
from clingo.ast import Transformer, parse_string
from scenic.domains.driving.roads import Network
from scenariogen.core.utils import geometry_atoms, classify_intersection
from scenariogen.core.events import *
from scenariogen.predicates.predicates import TemporalOrder
from scenariogen.simulators.carla.utils import vehicleLightState_to_signal # TODO bring signal to driving domain

traffic_rules_file = classify_intersection(network, config['intersection']) + '.lp'
with open(f"src/scenariogen/predicates/{traffic_rules_file}", 'r') as f:
  encoding = f.read()

coverage_space = {}
class AtomNameRecorder(Transformer):
  def visit_SymbolicAtom(self, node):
    coverage_space[node.symbol.name] = set()
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
  coverage = {predicate_name:set() for predicate_name in coverage_space}
  with ctl.solve(yield_=True) as handle:
    for model in handle:
      for atom in model.symbols(atoms=True):
        coverage[atom.name].add(tuple(str(arg) for arg in atom.arguments))
  return coverage

coverage = {}
monitor CoverageMonitor():
  events = []
  cars = simulation().agents
  maneuvers = intersection.maneuvers
  arrived = {car: False for car in cars}
  entered = {car: False for car in cars}
  exited = {car: False for car in cars}
  lanes = {car: set() for car in cars}
  inIntersection = {car: False for car in cars}
  lightState = {car: None for car in cars}
  moving = {car: False for car in cars}
  for step in range(config['steps']):
    time_seconds = step * config['timestep']
    for car in cars:
      light_state = car.carlaActor.get_light_state()
      if lightState[car] != light_state:
        lightState[car] = light_state
        events.append(SignaledEvent(car.name, vehicleLightState_to_signal(light_state).name.lower(), time_seconds))

      if moving[car] and car.speed <= config['stopping_speed']:
        events.append(StoppedEvent(car.name, time_seconds))
        moving[car] = False
      elif (not moving[car]) and car.speed >= config['moving_speed']:
        events.append(MovedEvent(car.name, time_seconds))
        moving[car] = True

      inIntersection[car] = intersection.intersects(PolygonalRegion(polygon=car._boundingPolygon))
      
      if (not arrived[car]) and (distance from (front of car) to intersection) < config['arrival_distance']:
        arrived[car] = True
        events.append(ArrivedAtIntersectionEvent(car.name, car.lane.uid, time_seconds))
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
