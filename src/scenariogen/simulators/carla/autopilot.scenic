""" Scenario Description
Ego-vehicle driven by Carla's autopilot.
All nonegos' behaviors are predetermined.
"""
model scenic.simulators.carla.model

param config = None
config = globalParameters.config

param seed = None
seed = globalParameters.seed

intersection = network.elements[config['intersection']]

# Python imports
import time
import visualization
from rss_sensor import RssSensor
import carla
from signals import SignalType
from utils import sample_trajectory, get_trace
from agents.navigation.behavior_agent import BehaviorAgent
from scenic.simulators.carla.utils.utils import scenicToCarlaLocation

behavior AnimateBehavior():
	lights = self.signal.to_vehicleLightState()
	#take SetVehicleLightStateAction(lights)
	for pose in self.traj_sample:
		take SetTransformAction(pose.position, pose.heading)

behavior CarlaBehaviorAgent():
	take SetVehicleLightStateAction(signal.to_vehicleLightState())
	take SetAutopilotAction(True)
	agent = BehaviorAgent(self.carlaActor, behavior=config['aggressiveness'])
	carla_world = simulation().world
	route_lanes = [network.elements[l] for l in config['ego_route'].lanes]
	dest = scenicToCarlaLocation(route_lanes[-1].centerline[-1], world=carla_world)
	agent.set_destination(dest)
	rss_enabled = config['rss_enabled']
	if rss_enabled:
		transforms = [pair[0].transform for pair in plan]
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
for spline, signal, l, w, b in zip(seed.trajectories, seed.signals, seed.lengths, seed.widths, config['blueprints']):
	traj_sample = sample_trajectory(spline,
																	int(config['steps'])+1,
																	0,
																	config['timestep']*config['steps'])
	p0 = traj_sample[0]
	car = Car at p0,
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

ego_lanes = [network.elements[l] for l in config['ego_route'].lanes]
ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress'])
ego = Car at ego_init_pos,
	  with name 'ego',
		with color Color(0, 1, 0),
		with behavior CarlaBehaviorAgent(),
		with physics True,
		with allowCollisions True,
		with signal signal,
		with route config['ego_route']
cars.append(ego)


monitor showIntersection:
	carla_world = simulation().world
	visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
	visualization.set_camera(carla_world, intersection, height=50)
	wait