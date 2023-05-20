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

# Python imports
import visualization
from signals import SignalType
from utils import sample_trajectory
import time
import pickle
import carla

behavior AnimateBehavior():
	#lights = self.signal.to_vehicleLightState()
	#take SetVehicleLightStateAction(lights)
	for pose in self.traj_sample:
		take SetTransformAction(pose.position, pose.heading)

cars = []
for spline, signal in zip(seed.trajectories, seed.signals):
	traj_sample = sample_trajectory(spline,
																	int(config['steps'])+1,
																	0,
																	config['timestep']*config['steps'])
	car = Car at traj_sample[0],
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
	wait