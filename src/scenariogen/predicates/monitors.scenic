
from itertools import product
from scenic.core.regions import UnionRegion
from scenic.domains.driving.roads import Lane, Intersection

from scenariogen.predicates.events import *
from scenariogen.simulators.carla.utils import vehicleLightState_to_signal


monitor VehicleSignalMonitor(config, eventsOut):
  """
  """
  cars = simulation().agents
  signal = {car: None for car in cars}
  while True:
    time_seconds = simulation().currentTime * config['timestep']
    for car in cars:
      signal_curr = vehicleLightState_to_signal(car.carlaActor.get_light_state())
      if signal[car] != signal_curr:
        signal[car] = signal_curr
        eventsOut.append(SignaledEvent(car, signal_curr, time_seconds))
    wait


monitor ArrivingAtIntersectionMonitor(config, eventsOut):
  """
  Informal definition of an intersection arrival event:
    1. At the initial time step, no arrival event is generated. (Events happen on transitions, but at the beginning, no transitions have been observed yet.)
    2. At an arrival event, the front of the car is on an incoming lane to the intersection.
    2. At an arrival event, the distance of front of the car to the intersection is at most `arrival_distance`.
    3. At the time step prior to an arrival event, the distance of the front of the car to the intersection is bigger than `arrival_distance`.
  """
  # monitor parameters
  network = config['network']
  intersection = network.elements[config['intersection']]
  incomingLanes = UnionRegion(*intersection.incomingLanes)
  cars = simulation().agents
  pre_arrived = {car: True if (front of car) in incomingLanes and\
                              (distance from (front of car) to intersection) > config['arrival_distance']\
                           else False
                  for car in cars}
  while True:
    time_seconds = simulation().currentTime * config['timestep']
    for car in cars:
      # We assume that from the pre_arrived state, the only possible next states are pre_arrived and arrived.
      if pre_arrived[car]:
        if (distance from (front of car) to intersection) <= config['arrival_distance']:
          pre_arrived[car] = False
          eventsOut.append(ArrivedAtIntersectionEvent(car, network.laneAt(front of car), time_seconds))
      else:
        pre_arrived[car] = True if (front of car) in incomingLanes and\
                                   (distance from (front of car) to intersection) > config['arrival_distance']\
                                else False
    wait


monitor StoppingMonitor(config, eventsOut):
  """
  """
  cars = simulation().agents
  moving = {car: False for car in cars}
  while True:
    time_seconds = simulation().currentTime * config['timestep']    
    for car in cars:
      if moving[car] and car.speed <= config['stopping_speed']:
        eventsOut.append(StoppedEvent(car, time_seconds))
        moving[car] = False
      elif (not moving[car]) and car.speed >= config['moving_speed']:
        eventsOut.append(MovedEvent(car, time_seconds))
        moving[car] = True
    wait


monitor RegionOverlapMonitor(config, eventsOut):
  """
  1. At the initial step, cars are assumed to enter the regions that they occupy upon spawn, i.e. the entrance event is generated.
  """
  cars = simulation().agents
  occupiedRegions = {car: set(region.uid for region in config['regions'] if region.intersects(PolygonalRegion(polygon=car._boundingPolygon))) 
                    for car in cars}
  while True:
    time_seconds = simulation().currentTime * config['timestep']    
    for car, region in product(cars, config['regions']):
      wasOnRegion = region.uid in occupiedRegions[car]
      isOnRegion = region.intersects(PolygonalRegion(polygon=car._boundingPolygon))
      if isOnRegion and not wasOnRegion:
        eventsOut.append(EnteredRegionEvent(car, region, time_seconds))
        occupiedRegions[car].add(region.uid)
      elif wasOnRegion and not isOnRegion:
        eventsOut.append(LeftRegionEvent(car, region, time_seconds))
        occupiedRegions[car].remove(region.uid)
    wait