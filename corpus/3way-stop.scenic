""" Scenario Description
Two non-egos arrive at a 3way all-way-stop intersection,
	one from the major road and one from the minor road.
"""

#--- Python imports
import jsonpickle
from signals import SignalType
import seed_corpus

#--- Defined constants
carla_map = 'Town05'
intersection_uid = 'intersection1930'
traffic_rules = '3way-T_stopOnAll.lp'
ego_route = seed_corpus.Route(lanes=('road9_lane1', 'road10_lane1', 'road1940_lane0', 'road3_lane2'))
ego_init_progress = 40
arrival_distance = 4
route_major = seed_corpus.Route(lanes=['road24_lane0', 'road11_lane3', 'road1985_lane1', 'road10_lane3', 'road9_lane3'])
route_major2minor = seed_corpus.Route(lanes=['road3_lane1', 'road1946_lane0', 'road11_lane1', 'road24_lane2'])
turn_signals = [SignalType.OFF, SignalType.LEFT]

#--- Scenic parameters
param carla_map = carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.domains.driving.model

#--- Derived constants
intersection = network.elements[intersection_uid]
route_major_lanes = [network.elements[l] for l in route_major.lanes]
route_major_centerline = PolylineRegion.unionAll([l.centerline for l in route_major_lanes])
route_major2minor_lanes = [network.elements[l] for l in route_major2minor.lanes]
route_major2minor_centerline = PolylineRegion.unionAll([l.centerline for l in route_major2minor_lanes])
config = {'carla_map': carla_map,
          'map': globalParameters.map,
          'intersection': intersection_uid,
          'traffic_rules': traffic_rules,
          'ego_route': ego_route,
          'ego_init_progress': ego_init_progress
          }

with open('carla_blueprint_library.json', 'r') as f:
  blueprints = jsonpickle.decode(f.read())

behavior StopBehavior():
  take SetThrottleAction(0)
  take SetBrakeAction(1)
  while True:
    wait

behavior PassBehavior(speed, trajectory):
  do FollowTrajectoryBehavior(speed, trajectory) until (distance from (front of self) to intersection) <= arrival_distance
  do StopBehavior() until self.speed <= 0.1
  do FollowTrajectoryBehavior(speed, trajectory)
  do FollowLaneBehavior(speed)

p0_init_progress = 60
p0 = route_major_centerline.pointAlongBy(p0_init_progress)
car_left = Car at p0, facing roadDirection,
  with name 'nonego_left',
  with physics True,
  with allowCollisions False,
  with signal turn_signals[0],
  with behavior PassBehavior(4, route_major_lanes),
  with length blueprints['vehicle.tesla.model3']['length'],
  with width blueprints['vehicle.tesla.model3']['width']

p1_init_progress = 10
p1 = route_major2minor_centerline.pointAlongBy(p1_init_progress)
car_right = Car at p1, facing roadDirection,
  with name 'nonego_right',
  with physics True,
  with allowCollisions False,
  with signal turn_signals[1],
  with behavior PassBehavior(4, route_major2minor_lanes),
  with length blueprints['vehicle.ford.crown']['length'],
  with width blueprints['vehicle.ford.crown']['width']

ego = car_left

#--- Output parameters
record initial [route_major, route_major2minor] as routes
record initial turn_signals as turn_signals
record initial [car_left.length, car_right.length] as lengths
record initial [car_left.width, car_right.width] as widths
record initial config as config