""" Scenario Description
Ego-vehicle arrives at an intersection.
"""

# Scenic parameters
model scenic.domains.driving.model

# Python imports
import visualization
from signals import SignalType
from utils import sample_trajectory
from event_logger import EventLogger

param config = None
config = globalParameters.config

param seed = None
seed = globalParameters.seed

# Derived constants
intersection = network.elements[config['intersection']]
seconds = seed.trajectories[0].ctrlpts[-1][2]
steps = int(seconds / config['timestep'])
event_logger = EventLogger()

behavior AnimateBehavior():
	lights = self.signal.to_vehicleLightState()
	for pose in self.traj_sample:
		take SetPositionAction(pose.position), SetHeadingAction(pose.heading)

cars = []
for route, spline, signal in zip(seed.routes, seed.trajectories, seed.signals):
	traj_sample = sample_trajectory(spline, 
																	steps+1,
																	0, 
																	seconds)
	d0 = int(spline.ctrlpts[0][1])
	car = Car at traj_sample[0],
	  with name '_'.join(route.lanes + [str(d0)]),
		with color Color(0, 0, 1),
		with behavior AnimateBehavior(),
		with physics False,
		with allowCollisions False,
		with traj_sample traj_sample,
		with signal signal
	cars.append(car)
ego = cars[0]

monitor intersection_events:
	maneuvers = intersection.maneuvers
	arrived = {car: False for car in cars}
	entered = {car: False for car in cars}
	exited = {car: False for car in cars}
	lanes = {car: set() for car in cars}
	inIntersection = {car: False for car in cars}
	while True:
		currentTime = simulation().currentTime
		for car in cars:
			inIntersection[car] = intersection.intersects(car)
			
			if (not arrived[car]) and (distance from (front of car) to intersection) < config['arrival_distance']:
				arrived[car] = True
				event_logger.on_arrival(car.name, car.lane.uid, car.signal.name.lower(), currentTime)
			if inIntersection[car] and not entered[car]:
				entered[car] = True
				event_logger.on_entrance(car.name, car.lane.uid, currentTime)
			if entered[car] and (not exited[car]) and not inIntersection[car]:
				exited[car] = True
				event_logger.on_exit(car.name, car.lane.uid, currentTime)

			for maneuver in maneuvers:
				lane = maneuver.connectingLane
				wasOnLane = lane.uid in lanes[car]
				isOnLane = lane.intersects(car)
				if isOnLane and not wasOnLane:
					lanes[car].add(lane.uid)
					event_logger.on_enterLane(car.name, lane.uid, currentTime)
				elif wasOnLane and not isOnLane:
					lanes[car].remove(lane.uid)
					event_logger.on_exitLane(car.name, lane.uid, currentTime)
		wait

#--- Output parameters
record final event_logger.get_events() as events
