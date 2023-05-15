""" Scenario Description
Ego-vehicle driven by Carla's autopilot.
All nonegos' behaviors are predetermined.
"""
param map = localPath('./maps/Town05.xodr')  # or other CARLA map that definitely works
param carla_map = 'Town05'
model scenic.simulators.carla.model

# Python imports
import time
import visualization
from rss_sensor import RssSensor
import carla
from signals import SignalType
from utils import sample_route
from agents.navigation.behavior_agent import BehaviorAgent
from scenic.simulators.carla.utils.utils import scenicToCarlaLocation

behavior AnimateBehavior():
	lights = self.signal.to_vehicleLightState()
	#take SetVehicleLightStateAction(lights)
	carla_world = simulation().world
	for pose in self.route_sample:
		take SetTransformAction(pose.position, pose.heading)
		visualization.label_car(carla_world, self)

behavior CarlaBehaviorAgent():
	take SetVehicleLightStateAction(signal.to_vehicleLightState())
	take SetAutopilotAction(True)
	agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
	carla_world = simulation().world
	src = scenicToCarlaLocation(trajectory[self.name][0][0], world=carla_world)
	dest = scenicToCarlaLocation(trajectory[self.name][-1][0], world=carla_world)
	agent.set_destination(src, dest, clean=True)
	if rss_enabled:
		transforms = [pair[0].transform for pair in agent._local_planner.waypoints_queue]
		rss_sensor = RssSensor(self.carlaActor, carla_world, None, None, None, routing_targets=transforms)
		restrictor = carla.RssRestrictor()
		vehicle_physics = self.carlaActor.get_physics_control()
	agent.update_information()
	while agent.incoming_waypoint:
		control = agent.run_step()
		if rss_enabled:
			rss_proper_response = rss_sensor.proper_response if rss_sensor.response_valid else None
			if rss_proper_response:
				control = restrictor.restrict_vehicle_control(
						control, rss_proper_response, rss_sensor.ego_dynamics_on_route, vehicle_physics)
		self.carlaActor.apply_control(control)
		wait
		agent.update_information()

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

ego = Car at p0,
	  with name 'ego',
		with color Color(0, 1, 0),
		with behavior CarlaBehaviorAgent(),
		with physics True,
		with allowCollisions True,
		with route_sample route_sample,
		with signal signal
cars.append(ego)



monitor showIntersection:
	carla_world = simulation().world
	visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
	wait