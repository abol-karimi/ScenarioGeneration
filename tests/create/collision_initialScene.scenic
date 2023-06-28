""" Scenario Description
Two platoons of vehicles cross each other and collide at the intersection.
"""

#--- Python imports
import jsonpickle
from scenariogen.core.signals import SignalType
from scenariogen.core.seed import Route

#--- Defined constants
carla_map = 'Town05'
intersection_uid = 'intersection396'
traffic_rules = '4way-uncontrolled.lp'
ego_route = Route(lanes=('road9_lane2', 'road455_lane0', 'road45_lane1'))
ego_init_progress = 30
arrival_distance = 4
route = Route(lanes=['road44_lane1', 'road552_lane1', 'road45_lane1'])


#--- Scenic parameters
param carla_map = carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.domains.driving.model

#--- Derived constants
intersection = network.elements[intersection_uid]
route_lanes = [network.elements[l] for l in route.lanes]
route_centerline = PolylineRegion.unionAll([l.centerline for l in route_lanes])
config = {'carla_map': carla_map,
          'map': globalParameters.map,
          'intersection': intersection_uid,
          'traffic_rules': traffic_rules,
          'ego_route': ego_route,
          'ego_init_progress': ego_init_progress
          }

with open('src/scenariogen/simulators/carla/blueprint_library.json', 'r') as f:
  blueprints = jsonpickle.decode(f.read())

cars = []
  
spawn_points = [route_lanes[0].centerline.pointAlongBy(d) 
                for d in [20, 24]]
for p in spawn_points:
  car = Car at p, facing roadDirection,
    with physics True,
    with allowCollisions False,
    with behavior FollowTrajectoryBehavior(3, route_lanes),
    with length blueprints['vehicle.tesla.model3']['length'],
    with width blueprints['vehicle.tesla.model3']['width']
  cars.append(car)

ego = cars[0]

#--- Output parameters
record initial [route, route] as routes
record initial [SignalType.OFF for car in cars] as turn_signals
record initial [car.length for car in cars] as lengths
record initial [car.width for car in cars] as widths
record initial config as config