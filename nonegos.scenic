""" Scenario Description
Ego-vehicle arrives at an intersection.
"""
param map = localPath('./maps/Town05.xodr')  # or other CARLA map that definitely works
param carla_map = 'Town05'
model scenic.simulators.carla.model

param config = None
config = globalParameters.config

param seed = None
seed = globalParameters.seed

param event_monitor = None
event_monitor = globalParameters.event_monitor

intersection = network.elements[config['intersection_uid']]
sample_size = int(config['maxSteps'])+1

# Python imports
import visualization
from signals import SignalType
from utils import sample_route

behavior AnimateBehavior():
	lights = self.signal.to_vehicleLightState()
	#take SetVehicleLightStateAction(lights)
	carla_world = simulation().world
	for pose in self.route_sample:
		take SetTransformAction(pose.position, pose.heading)
		visualization.label_car(carla_world, self)

cars = []
for route, spline, signal in zip(seed.routes, seed.curves, seed.signals):
	lanes = [network.elements[l_id] for l_id in route.lanes]
	route_sample = sample_route(lanes, spline, sample_size)
	d0 = int(spline.ctrlpts[0][1])
	p0 = route_sample[0]
	car = Car at p0,
	  with name '_'.join(route.lanes + [str(d0)]),
		with color Color(0, 0, 1),
		with behavior AnimateBehavior(),
		with physics False,
		with allowCollisions True,
		with route_sample route_sample,
		with signal signal
	cars.append(car)
ego = cars[0]

monitor intersection_events:
	carla_world = simulation().world
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
				event_monitor.on_arrival(car.name, car.lane.uid, car.signal, currentTime)
			if inIntersection[car] and not entered[car]:
				entered[car] = True
				event_monitor.on_entrance(car.name, car.lane.uid, currentTime)
			if entered[car] and (not exited[car]) and not inIntersection[car]:
				exited[car] = True
				event_monitor.on_exit(car.name, car.lane.uid, currentTime)

			for maneuver in maneuvers:
				lane = maneuver.connectingLane
				wasOnLane = lane.uid in lanes[car]
				isOnLane = lane.intersects(car)
				if isOnLane and not wasOnLane:
					lanes[car].add(lane.uid)
					event_monitor.on_enterLane(car.name, lane.uid, currentTime)
				elif wasOnLane and not isOnLane:
					lanes[car].remove(lane.uid)
					event_monitor.on_exitLane(car.name, lane.uid, currentTime)
		wait

monitor showIntersection:
	carla_world = simulation().world
	visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
	wait

