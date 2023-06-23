""" Scenario Description
Ego-vehicle arrives at an intersection.
"""
model scenic.simulators.carla.model

param config = None
config = globalParameters.config

param seed = None
seed = globalParameters.seed

intersection = network.elements[config['intersection']]

# Python imports
import time
import pickle
import carla
import visualization
from scenariogen.core.signals import SignalType
from scenariogen.core.utils import sample_trajectory

behavior AnimateBehavior():
	for pose in self.traj_sample:
		take SetTransformAction(pose.position, pose.heading)

cars = []
for spline, signal, l, w, b in zip(seed.trajectories, seed.signals, seed.lengths, seed.widths, config['blueprints']):
	traj_sample = sample_trajectory(spline,
																	int(config['steps'])+1,
																	0,
																	config['timestep']*config['steps'])
	car = Car at traj_sample[0],
		with color Color(0, 0, 1),
		with behavior AnimateBehavior(),
		with physics False,
		with allowCollisions False,
		with traj_sample traj_sample,
		with signal signal,
		with length l,
		with width w,
		with blueprint b
	cars.append(car)
ego = cars[0]

monitor showIntersection:
	carla_world = simulation().world
	visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
	visualization.set_camera(carla_world, intersection, height=50)
	wait