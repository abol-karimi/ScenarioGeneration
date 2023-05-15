""" Scenario Description
Ego-vehicle arrives at an intersection.
"""
param map = localPath('./maps/Town05.xodr')
model scenic.simulators.newtonian.driving_model
#simulator NewtonianSimulator(network, render=render)

param intersection_uid = 'intersection396'
intersection = network.elements[globalParameters.intersection_uid]

param lanes = None
lanes = globalParameters.lanes

param event_monitor = None
event_monitor = globalParameters.event_monitor

#CONSTANTS
SPEED = 4
ARRIVAL_DISTANCE = 4 # meters

behavior PassBehavior(speed, trajectory):
	try:
		do FollowTrajectoryBehavior(speed, trajectory)
	interrupt when (distance from self to trajectory[2].centerline[-1]) <= 1:
		abort
	take SetBrakeAction(1.0)

#Ego vehicle
ego = Car following roadDirection from lanes[0].centerline[0] for 0.0,
	with name 'ego',
	with behavior PassBehavior(SPEED, lanes)

#behavior AnimatedBehavior(speed, lane):
#	while (distance from self.position to lane) <= 0:
#		dt = simulation().timestep
#		pose = OrientedPoint following roadDirection from self.position for speed * dt
#		take SetTransformAction(pose.position, pose.heading)

monitor lane_events:
	maneuvers = intersection.maneuvers
	arrived = False
	entered = False
	exited = False
	lanes = set()
	while True:
		currentTime = simulation().currentTime
		inIntersection = intersection.intersects(ego)
		
		if (not arrived) and (distance from (front of ego) to intersection) < ARRIVAL_DISTANCE:
			arrived = True
			event_monitor.on_arrival(ego.name, ego.lane.uid, currentTime)
		if inIntersection and not entered:
			entered = True
			event_monitor.on_entrance(ego.name, ego.lane.uid, currentTime)
		if entered and (not exited) and not inIntersection:
			exited = True
			event_monitor.on_exit(ego.name, ego.lane.uid, currentTime)

		for maneuver in maneuvers:
			lane = maneuver.connectingLane
			wasOnLane = lane.uid in lanes
			isOnLane = lane.intersects(ego)
			if isOnLane and not wasOnLane:
				lanes.add(lane.uid)
				event_monitor.on_enterLane(ego.name, lane.uid, currentTime)
			elif wasOnLane and not isOnLane:
				lanes.remove(lane.uid)
				event_monitor.on_exitLane(ego.name, lane.uid, currentTime)
		wait