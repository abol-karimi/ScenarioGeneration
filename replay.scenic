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

intersection = network.elements[config['intersection_uid']]
sample_size = int(config['maxSteps'])+1

# Python imports
import visualization
from signals import SignalType
from utils import sample_route
import time

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

monitor showIntersection:
	carla_world = simulation().world
	visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
	wait