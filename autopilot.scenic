""" Scenario Description
Ego-vehicle driven by Carla's autopilot.
All nonegos' behaviors are predetermined.
"""
param map = localPath('./maps/Town05.xodr')  # or other CARLA map that definitely works
param carla_map = 'Town05'
model scenic.simulators.carla.model

param replay_scenario = None
replay_scenario = globalParameters.replay_scenario
intersection = network.elements[replay_scenario.intersection_uid]
maneuver_uid = replay_scenario.maneuver_uid
trajectory = replay_scenario.trajectory
blueprints = replay_scenario.blueprints
events = replay_scenario.events

param event_monitor = None
event_monitor = globalParameters.event_monitor

param stop_speed_threshold = 0.01  # meters/seconds
stop_speed_threshold = globalParameters.stop_speed_threshold

param aggressiveness = 'normal'
aggressiveness = globalParameters.aggressiveness

import visualization
from signals import vehicleLightState_from_maneuverType

ARRIVAL_DISTANCE = 4 # meters

car2time2signal = {car:{e.frame:e.signal for e in es if e.name == 'signaledAtForkAtTime'} 
	for car, es in events.items()}

behavior ReplayBehavior(): # for nonegos
	carla_world = simulation().world

	while True:
		t = simulation().currentTime
		state = trajectory[t][self.name]
		take SetTransformAction(state[0], state[1])

		if t in car2time2signal[self.name]:
			lights = SignalType[car2time2signal[self.name][t].upper()].to_vehicleLightState()
			take SetVehicleLightStateAction(lights)
		
		visualization.label_car(carla_world, self)

from agents.navigation.behavior_agent import BehaviorAgent
from scenic.simulators.carla.utils.utils import scenicToCarlaLocation

from signals import SignalType
l0_uid, l1_uid, l2_uid = maneuver_uid['ego']
l0 = network.elements[l0_uid]
l1 = network.elements[l1_uid]
l2 = network.elements[l2_uid]
maneuverType = ManeuverType.guessTypeFromLanes(l0, l2, l1)
signal = SignalType.from_maneuverType(maneuverType)

behavior CarlaBehaviorAgent():
	take SetVehicleLightStateAction(signal.to_vehicleLightState())
	take SetAutopilotAction(True)
	agent = BehaviorAgent(self.carlaActor, behavior=aggressiveness)
	carla_world = simulation().world
	src = scenicToCarlaLocation(trajectory[0][self.name][0], world=carla_world)
	dest = scenicToCarlaLocation(trajectory[-1][self.name][0], world=carla_world)
	agent.set_destination(src, dest, clean=True)
	agent.update_information()
	while agent.incoming_waypoint:
		control = agent.run_step()
		self.carlaActor.apply_control(control)
		wait
		agent.update_information()

for carName, carState in trajectory[0].items():
	if not carName in {'ego', 'illegal'}:
		car = Car at carState[0], facing carState[1],
			with name carName,
			with blueprint blueprints[carName],
			with behavior ReplayBehavior(),
			with physics False
	elif carName == 'ego':
		ego = Car at carState[0], facing carState[1],
			with name carName,
			with blueprint blueprints[carName],
			with behavior CarlaBehaviorAgent()

monitor egoEvents:
	carla_world = simulation().world
	visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
	maneuvers = intersection.maneuvers
	arrived = False
	stopped = False
	entered = False
	exited = False
	lanes = set()
	while True:
		currentTime = simulation().currentTime
		visualization.label_car(carla_world, ego)
		inIntersection = intersection.intersects(ego)
		
		if (not arrived) and (distance from (front of ego) to intersection) < ARRIVAL_DISTANCE:
			arrived = True
			event_monitor.on_arrival('ego', ego.lane.uid, signal.name.lower(), currentTime)
		if inIntersection and not entered:
			entered = True
			event_monitor.on_entrance('ego', ego.lane.uid, currentTime)
		if entered and (not exited) and not inIntersection:
			exited = True
			event_monitor.on_exit('ego', ego.lane.uid, currentTime)
		if arrived and (not entered) and (not stopped) and ego.speed <= stop_speed_threshold:
			stopped = True
			# if ego.lane has a stop sign:
			event_monitor.on_stop('ego', ego.lane.uid, currentTime)

		for maneuver in maneuvers:
			lane = maneuver.connectingLane
			wasOnLane = lane in lanes
			isOnLane = lane.intersects(ego)
			if isOnLane and not wasOnLane:
				lanes.add(lane)
				event_monitor.on_enterLane('ego', lane.uid, currentTime)
			elif wasOnLane and not isOnLane:
				lanes.remove(lane)
				event_monitor.on_exitLane('ego', lane.uid, currentTime)
		wait