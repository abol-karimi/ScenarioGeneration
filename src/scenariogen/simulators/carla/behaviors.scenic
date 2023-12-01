# Scenic parameters
model scenic.simulators.carla.model

# imports
import carla
# from examples.rss.rss_sensor import RssSensor
from agents.navigation.behavior_agent import BehaviorAgent
from scenic.simulators.carla.utils.utils import scenicToCarlaLocation
from scenariogen.simulators.carla.rss_sensor import RssSensor # TODO replace with carla module above
from scenariogen.simulators.carla.utils import signal_to_vehicleLightState, maneuverType_to_Autopilot_turn
import scenariogen.simulators.carla.visualization as visualization


behavior AutopilotRouteBehavior(maneuver_types, config_override={}):
	defaults = {
		'auto_lane_change': Uniform(True, False),
		'distance_to_leading_vehicle': Range(1, 10), # i.e. minimum moving distance
		'ignore_lights_percentage': Range(0, 100),
		'ignore_signs_percentage': Range(0, 100),
		'random_left_lanechange_percentage': Range(0, 100),
		'random_right_lanechange_percentage': Range(0, 100),
		'update_vehicle_lights': Uniform(True, False),
	}
	config = {**defaults, **config_override}

	simulation().tm.auto_lane_change(self.carlaActor, config['auto_lane_change'])
	simulation().tm.distance_to_leading_vehicle(self.carlaActor, config['distance_to_leading_vehicle'])
	simulation().tm.ignore_lights_percentage(self.carlaActor, config['ignore_lights_percentage'])
	simulation().tm.ignore_signs_percentage(self.carlaActor, config['ignore_signs_percentage'])
	simulation().tm.random_left_lanechange_percentage(self.carlaActor, config['random_left_lanechange_percentage'])
	simulation().tm.random_right_lanechange_percentage(self.carlaActor, config['random_right_lanechange_percentage'])
	simulation().tm.update_vehicle_lights(self.carlaActor, config['update_vehicle_lights'])

	turns = [maneuverType_to_Autopilot_turn(m) for m in maneuver_types]
	simulation().tm.set_route(self.carlaActor, turns)
	take SetAutopilotAction(True)


behavior AutopilotPathBehavior(path):
	for p in path:
		visualization.draw_point(simulation().world, p, 1,
															size=0.1,
															color=carla.Color(255, 0, 0),
															lifetime=120)

	print(f'Turning autopilot on for {self.name} at step {simulation().currentTime}...')
	# Use turn signals when turning:
	simulation().tm.update_vehicle_lights(self.carlaActor, True)
	# Follow traffic rules:
	simulation().tm.ignore_signs_percentage(self.carlaActor, 0)	
	# No lane changes as we are interested in behavior at intersections:
	simulation().tm.random_left_lanechange_percentage(self.carlaActor, 0)
	simulation().tm.random_right_lanechange_percentage(self.carlaActor, 0)
	simulation().tm.auto_lane_change(self.carlaActor, False)

	carla_path = [scenicToCarlaLocation(wp, world=simulation().world) for wp in path]
	simulation().tm.set_path(self.carlaActor, carla_path)
	take SetAutopilotAction(True)


behavior BehaviorAgentReachDestination(dest, aggressiveness='normal', debug=debug):
	agent = BehaviorAgent(self.carlaActor,
												behavior=aggressiveness,
												map_inst=simulation().map)
	agent.set_destination(scenicToCarlaLocation(dest, world=simulation().world),
												start_location=scenicToCarlaLocation(self.position, world=simulation().world))
	while not agent.done():
		control = agent.run_step(debug=debug)
		self.carlaActor.apply_control(control)
		wait

	print(f'Car {self.name} reached its destination.')


behavior BehaviorAgentRSSReachDestination(dest, aggressiveness='normal'):
	agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
	agent.set_destination(scenicToCarlaLocation(dest, world=simulation().world))

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
	print(f'Car {self.name} reached its destination.')


behavior BehaviorAgentFollowWaypoints(waypoints, aggressiveness):
	agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
	carla_world = simulation().world

	for wp in waypoints:
		agent.set_destination(scenicToCarlaLocation(wp, world=carla_world))
		while not agent.done():
			self.carlaActor.apply_control(agent.run_step())
			wait

	print(f'Car {self.name} reached its last waypoint.')

	take SetThrottleAction(0), SetBrakeAction(1), SetSteerAction(0)


behavior BehaviorAgentRSSFollowWaypoints(waypoints, aggressiveness):
	agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
	carla_world = simulation().world

	# TODO

