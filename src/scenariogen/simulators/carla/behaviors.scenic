# Scenic parameters
model scenic.simulators.carla.model

# imports
import carla
from agents.navigation.behavior_agent import BehaviorAgent
from scenic.simulators.carla.utils.utils import scenicToCarlaLocation
from scenariogen.simulators.carla.rss_sensor import RssSensor
from scenariogen.simulators.carla.utils import signal_to_vehicleLightState
from scenariogen.core.signals import SignalType

behavior AutopilotReachDestination(route, aggressiveness, use_rss):
	waypoints_separation = 50
	take SetVehicleLightStateAction(signal_to_vehicleLightState(self.signal))
	take SetAutopilotAction(True)
	agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
	carla_world = simulation().world
	lanes = [network.elements[uid] for uid in route]
	centerline = PolylineRegion.unionAll([l.centerline for l in lanes])
	dest = scenicToCarlaLocation(lanes[-1].centerline[-1], world=carla_world)
	agent.set_destination(dest)
	if not use_rss:
		while not agent.done():
			self.carlaActor.apply_control(agent.run_step())
			wait
	else:
		transforms = [pair[0].transform for pair in agent._local_planner._waypoints_queue]
		rss_sensor = RssSensor(self.carlaActor, carla_world, 
														None, None, None,
														routing_targets=transforms)
		restrictor = carla.RssRestrictor()
		vehicle_physics = self.carlaActor.get_physics_control()
		while not agent.done():
			control = agent.run_step()
			rss_proper_response = rss_sensor.proper_response if rss_sensor.response_valid else None
			if rss_proper_response:
				control = restrictor.restrict_vehicle_control(
						control, rss_proper_response, rss_sensor.ego_dynamics_on_route, vehicle_physics)
			self.carlaActor.apply_control(control)
			wait

behavior AutopilotFollowWaypoints(waypoints, aggressiveness, use_rss):
	take SetVehicleLightStateAction(signal_to_vehicleLightState(self.signal))
	take SetAutopilotAction(True)
	agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
	carla_world = simulation().world
	if not use_rss:
		for wp in waypoints:
			agent.set_destination(scenicToCarlaLocation(wp, world=carla_world))
			while not agent.done():
				self.carlaActor.apply_control(agent.run_step())
				wait
	else:
		# TODO apply waypoints as above
		dest = scenicToCarlaLocation(route_lanes[-1].centerline[-1], world=carla_world)
		agent.set_destination(dest)
		transforms = [pair[0].transform for pair in agent._local_planner._waypoints_queue]
		rss_sensor = RssSensor(self.carlaActor, carla_world, 
														None, None, None,
														routing_targets=transforms)
		restrictor = carla.RssRestrictor()
		vehicle_physics = self.carlaActor.get_physics_control()
		while not agent.done():
			control = agent.run_step()
			rss_proper_response = rss_sensor.proper_response if rss_sensor.response_valid else None
			if rss_proper_response:
				control = restrictor.restrict_vehicle_control(
						control, rss_proper_response, rss_sensor.ego_dynamics_on_route, vehicle_physics)
			self.carlaActor.apply_control(control)
			wait