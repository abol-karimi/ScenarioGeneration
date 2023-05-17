""" Scenario Description
Ego-vehicle driven by Carla's autopilot.
All nonegos' behaviors are predetermined.
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
import time
import visualization
from rss_sensor import RssSensor
import carla
from signals import SignalType
from utils import sample_trajectory
from agents.navigation.behavior_agent import BehaviorAgent
from scenic.simulators.carla.utils.utils import scenicToCarlaLocation

behavior AnimateBehavior():
	lights = self.signal.to_vehicleLightState()
	#take SetVehicleLightStateAction(lights)
	carla_world = simulation().world
	for pose in self.traj_sample:
		take SetTransformAction(pose.position, pose.heading)
		visualization.label_car(carla_world, self)

behavior CarlaBehaviorAgent():
	take SetVehicleLightStateAction(signal.to_vehicleLightState())
	take SetAutopilotAction(True)
	agent = BehaviorAgent(self.carlaActor, behavior=config['aggressiveness'])
	carla_world = simulation().world
	src = scenicToCarlaLocation(self.position, world=carla_world)
	dest = scenicToCarlaLocation(self.destination, world=carla_world)
	agent.set_destination(dest, src)
	rss_enabled = config['rss_enabled']
	if rss_enabled:
		transforms = [pair[0].transform for pair in agent._local_planner._waypoints_queue]
		rss_sensor = RssSensor(self.carlaActor, carla_world, 
														None, None, None,
														routing_targets=transforms)
		restrictor = carla.RssRestrictor()
		vehicle_physics = self.carlaActor.get_physics_control()
	while not agent.done():
		control = agent.run_step()
		control.manual_gear_shift = False
		if rss_enabled:
			rss_proper_response = rss_sensor.proper_response if rss_sensor.response_valid else None
			if rss_proper_response:
				control = restrictor.restrict_vehicle_control(
						control, rss_proper_response, rss_sensor.ego_dynamics_on_route, vehicle_physics)
		self.carlaActor.apply_control(control)
		wait

cars = []
for route, spline, signal in zip(seed.routes, seed.curves, seed.signals):
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

ego_lane = network.elements[config['ego_route'][0]]
ego = Car following roadDirection from ego_lane.centerline[-1] for -15,
	  with name 'ego',
		with color Color(0, 1, 0),
		with behavior CarlaBehaviorAgent(),
		with physics True,
		with allowCollisions True,
		with signal signal,
		with destination (Point on network.elements[config['ego_route'][1]])
cars.append(ego)



monitor showIntersection:
	carla_world = simulation().world
	visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
	wait