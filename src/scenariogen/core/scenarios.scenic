# Scenic parameters
model scenic.domains.driving.model
config = globalParameters.config
intersection = network.elements[config['intersection']]

# Python imports
from shapely.geometry import LineString

from scenariogen.core.events import *
from scenariogen.core.utils import sample_trajectories
from scenariogen.core.signals import SignalType
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError
from scenariogen.core.utils import is_collision_free
from scenariogen.core.geometry import CurvilinearTransform

behavior AnimateBehavior():
	for pose in self.traj_sample:
		take SetTransformAction(pose.position, pose.heading)

behavior StopAndPassIntersectionBehavior(speed, trajectory, intersection, arrival_distance=4):
  do FollowTrajectoryBehavior(speed, trajectory) until (distance from (front of self) to intersection) <= arrival_distance
  do StopBehavior() until self.speed <= 0.1
  do FollowTrajectoryBehavior(speed, trajectory)
  do FollowLaneBehavior(speed)

scenario NonegosScenario():
  setup:
    cars = []
    seed = config['seed']
    tjs = sample_trajectories(seed,
                              int(config['steps'])+1,
                              0, 
                              config['timestep']*config['steps'])
    for i, (route, tj, signal, l, w, bp) in enumerate(zip(seed.routes, tjs, seed.signals, seed.lengths, seed.widths, config['blueprints'])):
      car = Car at tj[0],
        with name f'{route[0]}_{signal.name}_{i}',
        with behavior AnimateBehavior(),
        with physics False,
        with allowCollisions False,
        with traj_sample tj,
        with signal signal,
        with length l,
        with width w,
        with blueprint bp
      cars.append(car)
    ego = cars[0]


events = []
scenario RecordEventsScenario(cars):
  setup:
    ego = cars[0]
    record final events as events

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

scenario CheckCollisionsScenario(egos, nonegos):
  setup:
    ego = (egos+nonegos)[0]

    monitor collisions:
      nonego_pairs = [(nonegos[i], nonegos[j]) 
              for i in range(len(nonegos)) 
              for j in range(i+1, len(nonegos))]
      ego_nonego_pairs = [(e, n) for e in egos for n in nonegos]
      while True:
        # Nonego-nonego collisions
        for c, d in nonego_pairs:
          if c.intersects(d):
            raise NonegoNonegoCollisionError(c, d)
        # Ego-nonego collisions
        for e, n in ego_nonego_pairs:
          if e.intersects(n):
            raise EgoCollisionError(e, n)
        wait

scenario ShowIntersection():
  setup:
    import scenariogen.simulators.carla.visualization as visualization
    from scenic.simulators.carla.simulator import CarlaSimulation
    
    monitor show_intersection:
      if isinstance(simulation(), CarlaSimulation):
        carla_world = simulation().world
        visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
        visualization.set_camera(carla_world, intersection, height=50)
      wait

positions = []
transforms = []
scenario RecordSeedInfoScenario(cars):
  setup:
    for car in cars:
      axis_coords = [p for uid in car.route for p in network.elements[uid].centerline.lineString.coords]
      transforms.append(CurvilinearTransform(axis_coords))

    record final config as config
    record tuple(transform.curvilinear(car.position) for car, transform in zip(cars, transforms)) as positions
    record final tuple(car.route for car in cars) as routes
    record final tuple(car.signal for car in cars) as turn_signals
    record final tuple(car.length for car in cars) as lengths
    record final tuple(car.width for car in cars) as widths


poses = []
scenario RecordSimTrajectories(cars):
  setup:

    monitor record_poses:
      while True:
        poses.append(tuple((car.position, car.heading) for car in cars))
        wait

    record final poses as poses