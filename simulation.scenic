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
from scenic.core.vectors import PiecewiseVectorField
from utils import sample_spline

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

behavior ReplayBehavior():
	carla_world = simulation().world
	while True:
		p0 = self.lanes[0].centerline[0]
		t = simulation().currentTime
		d = self.curve_sampled[t]
		pose = OrientedPoint following PiecewiseVectorField(name=self.route, regions=self.lanes) from p0 for d0
		take SetTransformAction(pose.position, pose.heading)

		visualization.label_car(carla_world, self)

route = config['ego_route']
lanes = [network.elements[l_id] for l_id in route]
p0 = lanes[0].centerline[1]
d0 = config['ego_distance']
ego = Car following PiecewiseVectorField(route, lanes) from p0 for d0,
		with name 'ego',
		with color Color(0, 1, 0),
		with behavior CarlaBehaviorAgent(),
		with physics True

for route, curve in zip(seed.routes, seed.curves):
	d0 = curve.ctrlpts[0].d
	lanes = [network.elements[l_id] for l_id in route]
	p0 = lanes[0].centerline[1]
	route_id = str(route)
	car = Car following PiecewiseVectorField(route_id, lanes) from p0 for d0,
		with color Color(0, 0, 1),
		with behavior ReplayBehavior(),
		with physics False,
		with route route,
		with curve_sampled sample_spline(curve.ctrlpts, sample_size),
		with lanes lanes

monitor showIntersection:
	carla_world = simulation().world
	visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
	wait