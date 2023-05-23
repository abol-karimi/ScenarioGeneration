""" Scenario Description
Two non-egos arrive at the intersection simultaneously,
	one is to the right of the other,
	and they both proceed simultaneously.
"""

#--- Model and parameters
param map = localPath('../maps/Town05.xodr')
param carla_map = 'Town05'
model scenic.domains.driving.model

#--- Python imports
import jsonpickle
from signals import SignalType
import seed_corpus

#--- Constants
intersection_uid = 'intersection396'
intersection = network.elements[intersection_uid]
arrival_distance = 4
route_left = seed_corpus.Route(lanes=['road44_lane1', 'road552_lane1', 'road45_lane1'])
route_right = seed_corpus.Route(lanes=['road8_lane1', 'road415_lane1', 'road9_lane1'])
turn_signals = [SignalType.OFF, SignalType.OFF]

with open('carla_blueprint_library.json', 'r') as f:
  blueprints = jsonpickle.decode(f.read())

behavior StopBehavior():
  take SetThrottleAction(0)
  take SetBrakeAction(1)
  while True:
    wait

behavior PassBehavior(speed, trajectory):
  do FollowTrajectoryBehavior(speed, trajectory) until (distance from (front of self) to trajectory[1]) <= arrival_distance
  do StopBehavior() until self.speed <= 0.1
  do FollowTrajectoryBehavior(speed, trajectory)

p0_dist = 15
trajectory = [network.elements[l] for l in route_left.lanes]
p0 = trajectory[0].centerline.pointAlongBy(p0_dist)
car_left = Car at p0, facing roadDirection,
  with name 'nonego_left',
  with physics True,
  with allowCollisions False,
  with signal turn_signals[0],
  with behavior PassBehavior(4, trajectory),
  with length blueprints['vehicle.tesla.model3']['length'],
  with width blueprints['vehicle.tesla.model3']['width']

p1_dist = 10
trajectory = [network.elements[l] for l in route_right.lanes]
p1 = trajectory[0].centerline.pointAlongBy(p1_dist)
car_right = Car at p1, facing roadDirection,
  with name 'nonego_right',
  with physics True,
  with allowCollisions False,
  with signal turn_signals[1],
  with behavior PassBehavior(4, trajectory),
  with length blueprints['vehicle.ford.crown']['length'],
  with width blueprints['vehicle.ford.crown']['width']

ego = car_left

#--- Output parameters
record initial [route_left, route_right] as routes
record initial turn_signals as turn_signals
record initial [car_left.length, car_right.length] as lengths
record initial [car_left.width, car_right.width] as widths