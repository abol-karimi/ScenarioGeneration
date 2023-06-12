model scenic.simulators.newtonian.driving_model

# Scenario parameters
param config = None
config = globalParameters.config

# Python imports
from events import *
from utils import sample_trajectory
from signals import SignalType

# Derived constants
seed = config['seed']
seconds = seed.trajectories[0].ctrlpts[-1][2]
steps = int(seconds / config['timestep'])

behavior AnimateBehavior():
	for pose in self.traj_sample:
		take SetPositionAction(pose.position), SetHeadingAction(pose.heading)

behavior StopAndPassIntersectionBehavior(speed, trajectory, intersection, arrival_distance=4):
  do FollowTrajectoryBehavior(speed, trajectory) until (distance from (front of self) to intersection) <= arrival_distance
  do StopBehavior() until self.speed <= 0.1
  do FollowTrajectoryBehavior(speed, trajectory)
  do FollowLaneBehavior(speed)

scenario Nonegos(cars):
  setup:
    seed = config['seed']
    for i, (route, spline, signal) in enumerate(zip(seed.routes, seed.trajectories, seed.signals)):
      traj_sample = sample_trajectory(spline, 
                                      steps+1,
                                      0, 
                                      seconds)
      car = Car at traj_sample[0],
        with name '_'.join(route.lanes + [str(i)]),
        with behavior AnimateBehavior(),
        with physics False,
        with allowCollisions False,
        with traj_sample traj_sample,
        with signal signal
      cars.append(car)
    ego = cars[0]

scenario IntersectionEvents(intersection, cars, log):
  setup:
    ego = cars[0]
 
    monitor record_events:
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
            log.append(ArrivedAtIntersectionEvent(car.name, car.lane.uid, currentTime))
            log.append(SignaledAtForkEvent(car.name, car.lane.uid, car.signal.name.lower(), currentTime))
          if inIntersection[car] and not entered[car]:
            entered[car] = True
            log.append(EnteredIntersectionEvent(car.name, car.lane.uid, currentTime))
          if entered[car] and (not exited[car]) and not inIntersection[car]:
            exited[car] = True
            log.append(ExitedIntersectionEvent(car.name, car.lane.uid, currentTime))

          for maneuver in maneuvers:
            lane = maneuver.connectingLane
            wasOnLane = lane.uid in lanes[car]
            isOnLane = car.intersects(lane)
            if isOnLane and not wasOnLane:
              lanes[car].add(lane.uid)
              log.append(EnteredLaneEvent(car.name, lane.uid, currentTime))
            elif wasOnLane and not isOnLane:
              lanes[car].remove(lane.uid)
              log.append(ExitedLaneEvent(car.name, lane.uid, currentTime))
        wait

scenario EgoFollowingLanes(cars):
  setup:
    ego_lanes = [network.elements[l] for l in config['ego_route'].lanes]
    ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
    ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress'])
    ego = Car at ego_init_pos,
        with name 'ego',
        with color Color(0, 1, 0),
        with behavior FollowLaneBehavior(target_speed=4),
        with physics True,
        with allowCollisions False,
        with signal SignalType.OFF
    cars.append(ego)