""" Animate the nonegos of a seed in Scenic's newtonian simulator.
"""
model scenic.simulators.newtonian.driving_model

param config = None
config = globalParameters.config

seed = config['seed']
intersection = network.elements[config['intersection']]

# Python imports
from scenariogen.core.signals import SignalType
from scenariogen.core.geometry import CurvilinearTransform

behavior AnimateBehavior():
	for pose in self.traj_sample:
		take SetPositionAction(pose.position), SetHeadingAction(pose.heading)

cars = []
for r, traj_sample, signal, l, w in zip(seed.routes, config['traj_samples'], seed.signals, seed.lengths, seed.widths):
	axis_coords = [p for uid in r for p in network.elements[uid].centerline.lineString.coords]
	transform = CurvilinearTransform(axis_coords)
	traj_sample_rectilinear = [transform.rectilinear(p) for p in traj_sample]
	car = Car at traj_sample_rectilinear[0],
		with color Color(0, 0, 1),
		with behavior AnimateBehavior(),
		with physics False,
		with allowCollisions False,
		with traj_sample traj_sample_rectilinear,
		with signal signal,
		with length l,
		with width w
	cars.append(car)
ego = cars[0]