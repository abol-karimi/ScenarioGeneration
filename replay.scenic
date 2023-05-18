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
from utils import sample_trajectory
import time
import pickle
import carla

behavior AnimateBehavior():
	lights = self.signal.to_vehicleLightState()
	#take SetVehicleLightStateAction(lights)
	carla_world = simulation().world
	for pose in self.traj_sample:
		take SetTransformAction(pose.position, pose.heading)
		visualization.label_car(carla_world, self)

cars = []
for route, spline, signal in zip(seed.routes, seed.trajectories, seed.signals):
	lanes = [network.elements[l_id] for l_id in route.lanes]
	traj_sample = sample_trajectory(spline, sample_size)
	p0 = traj_sample[0]
	car = Car at p0,
	  with name '_'.join(route.lanes + [str(p0)]),
		with color Color(0, 0, 1),
		with behavior AnimateBehavior(),
		with physics False,
		with allowCollisions True,
		with traj_sample traj_sample,
		with signal signal
	cars.append(car)
ego = cars[0]

monitor showIntersection:
	carla_world = simulation().world
	visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
	visualization.set_camera(carla_world, intersection, height=50)

	#debug
	with open('spacetime_trajectories.pickle', 'rb') as inFile:
		spacetime_trajectories = pickle.load(inFile)
	
	#--- Draw the simulated trajectories
	for tj in spacetime_trajectories:
		visualization.draw_points_3d(carla_world, tj)
	
	#--- Draw the spline approximation of the trajectories
	for car in cars:
		tj = car.traj_sample
		for i, p in enumerate(tj):
			visualization.draw_point_3d(carla_world, p, i*config['timestep'], 0.1, carla.Color(0, 0, 255))

	wait