""" Scenario Description
Two non-egos arrive at the intersection simultaneously,
	one is to the right of the other,
	and they both proceed simultaneously.
"""

#--- Model and parameters
param map = localPath('../maps/Town05.xodr')
param carla_map = 'Town05'
model scenic.domains.driving.model
param timestep = 0.05

#--- Python imports
from signals import SignalType
import seed_corpus

#--- Constants
intersection_uid = 'intersection396'
intersection = network.elements[intersection_uid]
arrival_distance = 4
route_left = seed_corpus.Route(lanes=['road44_lane1', 'road552_lane1', 'road45_lane1'])
route_right = seed_corpus.Route(lanes=['road8_lane1', 'road415_lane1', 'road9_lane1'])
turn_signals = [SignalType.OFF, SignalType.OFF]

behavior StopBehavior():
  while True:
    take SetThrottleAction(0)
    take SetBrakeAction(1)

behavior PassBehavior(speed, trajectory):
  arrived = False
  do FollowTrajectoryBehavior(speed, trajectory)
  # try:
  #   do FollowTrajectoryBehavior(speed, trajectory)
  # interrupt when (not arrived) and (distance from self to trajectory[1]) <= arrival_distance:
  #   arrived = True
  #   do StopBehavior() for 5 seconds
  # interrupt when (distance from self to trajectory[1]) <= .5:
  #   take SetBrakeAction(0)
  #   take SetHandBrakeAction(False)

p0_dist = 15
trajectory = [network.elements[l] for l in route_left.lanes]
p0 = trajectory[0].centerline.pointAlongBy(p0_dist)
car_left = Car at p0, facing roadDirection,
  with name 'nonego_left',
  with physics True,
  with allowCollisions False,
  with signal turn_signals[0],
  with behavior PassBehavior(4, trajectory)

p1_dist = 10
trajectory = [network.elements[l] for l in route_right.lanes]
p1 = trajectory[0].centerline.pointAlongBy(p1_dist)
car_right = Car at p1, facing roadDirection,
  with name 'nonego_right',
  with physics True,
  with allowCollisions False,
  with signal turn_signals[1],
  with behavior PassBehavior(4, trajectory)

ego = car_left

#--- Output parameters
record initial [route_left, route_right] as routes
record initial turn_signals as turn_signals