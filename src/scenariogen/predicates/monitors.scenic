
from scenariogen.simulators.carla.utils import vehicleLightState_to_signal

monitor ArrivingAtIntersectionMonitor(config):
  """
  Informal definition of an intersection arrival event:
    1. At the initial time step, no car has arrived. (Events happen on transitions, but at the beginning, no transitions have been observed yet.)
    2. At an arrival event, the front of the car is on an incoming lane to the intersection.
    2. At an arrival event, the distance of front of the car to the intersection is at most `arrival_distance`.
    3. At the time step prior to an arrival event, the distance of the front of the car to the intersection is bigger than `arrival_distance`.
  """
  # monitor parameters
  intersection = config['intersection']
  arrival_distance = config['arrival_distance']
  eventsOut = config['eventsOut']

  cars = simulation().agents
  incomingLanes = set(lane.uid for lane in intersection.incomingLanes)


monitor VehicleSignalMonitor(config):
  """
  """
  eventsOut = config['eventsOut']
  cars = simulation().agents
  lightState = {car: None for car in cars}
  while True:
    time_seconds = simulation().currentTime * config['timestep']
    for car in cars:
      light_state = car.carlaActor.get_light_state()
      if lightState[car] != light_state:
        signal = vehicleLightState_to_signal(light_state).name.lower()
        eventsOut.append(SignaledEvent(car.name, signal, time_seconds))
        lightState[car] = light_state

monitor StoppingMonitor(config):
  """
  """
  eventsOut = config['eventsOut']
  cars = simulation().agents
  moving = {car: False for car in cars}
  while True:
    for car in cars:
      if moving[car] and car.speed <= config['stopping_speed']:
        events.append(StoppedEvent(car.name, time_seconds))
        moving[car] = False
      elif (not moving[car]) and car.speed >= config['moving_speed']:
        events.append(MovedEvent(car.name, time_seconds))
        moving[car] = True

monitor RegionOverlapMonitor(config):
  """
  1. At the initial step, cars are assumed to enter the regions that they occupy upon spawn, i.e. the entrance event is generated.
  """
  eventsOut = config['eventsOut']
  cars = simulation().agents
  occupiedRegions = {car: set() for car in cars}
  while True:
    for region in config['regions']:
      wasOnRegion = region.uid in occupiedRegions[car]
      isOnRegion = region.intersects(PolygonalRegion(polygon=car._boundingPolygon))
      if isOnRegion and not wasOnRegion:
        occupiedRegions[car].add(region.uid)
        events.append(EnteredRegionEvent(car.name, region.uid, time_seconds))
      elif wasOnRegion and not isOnRegion:
        occupiedRegion[car].remove(region.uid)
        events.append(ExitedRegionEvent(car.name, region.uid, time_seconds))