""" Animate the nonegos of a seed in Scenic's newtonian simulator.
"""
model scenic.simulators.newtonian.driving_model

param config = None
config = globalParameters.config

seed = config['seed']
intersection = network.elements[config['intersection']]

# Python imports
from scenariogen.core.signals import SignalType
from scenariogen.core.utils import sample_trajectory

behavior AnimateBehavior():
	for pose in self.traj_sample:
		take SetPositionAction(pose.position), SetHeadingAction(pose.heading)

cars = []
for traj_sample, signal, l, w in zip(config['traj_samples'], seed.signals, seed.lengths, seed.widths):
	car = Car at traj_sample[0],
		with color Color(0, 0, 1),
		with behavior AnimateBehavior(),
		with physics False,
		with allowCollisions False,
		with traj_sample traj_sample,
		with signal signal,
		with length l,
		with width w
	cars.append(car)
ego = cars[0]