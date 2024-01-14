from itertools import product, permutations
import queue
import carla

from scenic.core.regions import UnionRegion
from scenic.domains.driving.roads import Lane, Intersection

from scenariogen.core.geometry import CurvilinearTransform
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
        eventsOut.append(SignaledEvent(car.name, signal_curr.name.lower(), time_seconds))
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
          eventsOut.append(ArrivedAtIntersectionEvent(car.name, network.laneAt(front of car).uid, time_seconds))
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
        eventsOut.append(StoppedEvent(car.name, time_seconds))
        moving[car] = False
      elif (not moving[car]) and car.speed >= config['moving_speed']:
        eventsOut.append(MovedEvent(car.name, time_seconds))
        moving[car] = True
    wait


monitor RegionOverlapMonitor(config, eventsOut):
  """
  Note: At the initial step, cars are assumed to enter the regions that they occupy upon spawn, i.e. the entrance event is generated.
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
        if isinstance(region, Lane):
          eventsOut.append(EnteredLaneEvent(car.name, region.uid, time_seconds))
        elif isinstance(region, Intersection):
          eventsOut.append(EnteredIntersectionEvent(car.name, car.lane.uid, time_seconds))
        occupiedRegions[car].add(region.uid)
      elif wasOnRegion and not isOnRegion:
        if isinstance(region, Lane):
          eventsOut.append(LeftLaneEvent(car.name, region.uid, time_seconds))
        elif isinstance(region, Intersection):
          eventsOut.append(LeftIntersectionEvent(car.name, car.lane.uid, time_seconds))
        occupiedRegions[car].remove(region.uid)
    wait


monitor OcclusionMonitor(config, eventsOut):
  """
  appearedToAtTime(V1, V2, T)
  disappearedFromAtTime(V1, V2, T)
  """
  cars = simulation().agents
  could_see = {(c1, c2):False for c1, c2 in permutations(cars, 2)}
  while True:
    time_seconds = simulation().currentTime * config['timestep']
    for c1, c2 in permutations(cars, 2):
      if (c1 can see c2) and not could_see[c1, c2]:
        could_see[c1, c2] = True
        eventsOut.append(AppearedToOtherEvent(c2.name, c1.name, time_seconds))
      elif (not c1 can see c2) and could_see[c1, c2]:
        could_see[c1, c2] = False
        eventsOut.append(DisappearedFromOtherEvent(c2.name, c1.name, time_seconds))
    wait


def on_collision(event, q):
  q.put(event)

 
monitor CarlaCollisionMonitor(config, eventsOut):
  event_queue = queue.Queue()
  carla_world = simulation().world
  bp = carla_world.get_blueprint_library().find('sensor.other.collision')
  sensors = []
  carla2scenic = {}
  for agent in simulation().agents:
    carla2scenic[agent.carlaActor.id] = agent.name
    sensor = carla_world.spawn_actor(bp, carla.Transform(), attach_to=agent.carlaActor)
    sensors.append(sensor)
    sensor.listen(lambda e: on_collision(e, event_queue))

  while (simulation().currentTime < config['steps']):
    time_seconds = simulation().currentTime * config['timestep']
    while not event_queue.empty():
      event = event_queue.get()
      actor_name = carla2scenic[event.actor.id]
      if event.other_actor.id in carla2scenic:
        other_name = carla2scenic[event.other_actor.id]
      else:
        other_name = f"{event.other_actor.type_id.replace('.', '_')}_{event.other_actor.id}"

      eventsOut.append(CollisionEvent(actor_name, other_name, time_seconds))
    wait
  
  for sensor in sensors:
    if sensor.is_listening():
      sensor.stop()
    sensor.destroy()

  wait


monitor ActorsMonitor(config, eventsOut):
  """In Scenic actors are not spawned or destroyed during the simulation,
  so we only need to check once."""
  for agent in simulation().agents:
    transform = CurvilinearTransform(agent.lane.centerline.lineString.coords)
    progress = transform.curvilinear(agent.position)[0]
    eventsOut.append(ActorSpawnedEvent(agent.name, agent.lane.uid, int(progress), 0))
  
  wait

# monitor TailgateMonitor(config, eventsOut):
#   """
#   startedTailgatingAtTime(V1, V2, T)
#   stoppedTailgatingAtTime(V1, V2, T)
#   """
#   cars = simulation().agents
#   while True:
#     # TODO
#     wait


# monitor RollingStopMonitor()
