""" Scenario Description
Two platoons of vehicles cross each other and collide at the intersection.
"""

#--- Python imports
import jsonpickle
from scenariogen.core.signals import SignalType

#--- Defined constants
carla_map = 'Town05'
intersection_uid = 'intersection396'
traffic_rules = '4way-uncontrolled.lp'
ego_route = ('road9_lane2', 'road455_lane0', 'road45_lane1')
ego_init_progress_ratio = 30
arrival_distance = 4
route_left = ('road44_lane1', 'road552_lane1', 'road45_lane1')
route_right = ('road8_lane1', 'road415_lane1', 'road9_lane1')

#--- Scenic parameters
param carla_map = carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.newtonian.driving_model

#--- Derived constants
intersection = network.elements[intersection_uid]
route_left_lanes = [network.elements[l] for l in route_left]
route_left_centerline = PolylineRegion.unionAll([l.centerline for l in route_left_lanes])
route_right_lanes = [network.elements[l] for l in route_right]
route_right_centerline = PolylineRegion.unionAll([l.centerline for l in route_right_lanes])
config = {'carla_map': carla_map,
          'map': globalParameters.map,
          'intersection': intersection_uid,
          'traffic_rules': traffic_rules,
          'ego_route': ego_route,
          'ego_init_progress_ratio': ego_init_progress_ratio
          }

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprints = jsonpickle.decode(f.read())

cars = []
  
distances = [30, 40, 50, 60]
spawn_points = [route_left_lanes[0].centerline.pointAlongBy(d) 
                for d in distances]
bp = 'vehicle.tesla.model3'
for p, d in zip(spawn_points, distances):
  car = Car at p, facing roadDirection,
    with name f'{bp}_{d}',
    with physics True,
    with allowCollisions False,
    with behavior FollowTrajectoryBehavior(3, route_left_lanes),
    with length blueprints[bp]['length'],
    with width blueprints[bp]['width'],
    with route route_left
  cars.append(car)

distances = [0, 9, 18, 27]
spawn_points = [route_right_lanes[0].centerline.pointAlongBy(d) 
                for d in distances]
bp = 'vehicle.carlamotors.firetruck'
for p, d in zip(spawn_points, distances):
  car = Car at p, facing roadDirection,
    with name f'{bp}_{d}',
    with physics True,
    with allowCollisions False,
    with behavior FollowTrajectoryBehavior(4, route_right_lanes),
    with length blueprints[bp]['length'],
    with width blueprints[bp]['width'],
    with route route_right
  cars.append(car)

ego = cars[0]

#--- Output parameters
record initial (car.route for car in cars) as routes
record initial (car.signal for car in cars) as signals
record initial (car.length for car in cars) as lengths
record initial (car.width for car in cars) as widths
record initial config as config