# Scenic parameters
model scenic.simulators.carla.model

# imports
import carla
from agents.navigation.behavior_agent import BehaviorAgent
from scenic.simulators.carla.utils.utils import scenicToCarlaLocation
from scenariogen.simulators.carla.rss_sensor import RssSensor
from scenariogen.core.utils import sample_trajectory

behavior AutopilotFollowRoute(route, aggressiveness, rss_enabled):
	take SetVehicleLightStateAction(self.signal.to_vehicleLightState())
	take SetAutopilotAction(True)
	agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
	carla_world = simulation().world
	route_lanes = [network.elements[l] for l in route]
	dest = scenicToCarlaLocation(route_lanes[-1].centerline[-1], world=carla_world)
	agent.set_destination(dest)
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