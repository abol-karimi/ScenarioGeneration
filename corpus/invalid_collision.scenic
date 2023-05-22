""" Scenario Description
Two platoons of vehicles cross each other and collide at the intersection.
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

with open('carla_blueprint_library.json', 'r') as f:
  blueprints = jsonpickle.decode(f.read())

cars = []
  
trajectory = [network.elements[l] for l in route_left.lanes]
spawn_points = [trajectory[0].centerline.pointAlongBy(d) 
                for d in [10, 16, 32, 36]]
for p in spawn_points:
  car = Car at p, facing roadDirection,
    with physics True,
    with allowCollisions False,
    with behavior FollowTrajectoryBehavior(3, trajectory),
    with length blueprints['vehicle.tesla.model3']['length'],
    with width blueprints['vehicle.tesla.model3']['width']
  cars.append(car)

trajectory = [network.elements[l] for l in route_right.lanes]
spawn_points = [trajectory[0].centerline.pointAlongBy(d) 
                for d in [10, 16, 32, 36]]
for p in spawn_points:
  car = Car at p, facing roadDirection,
    with physics True,
    with allowCollisions False,
    with behavior FollowTrajectoryBehavior(3, trajectory),
    with length blueprints['vehicle.ford.crown']['length'],
    with width blueprints['vehicle.ford.crown']['width']
  cars.append(car)

ego = cars[0]

#--- Output parameters
record initial (route_left*4 + route_right*4) as routes
record initial [SignalType.OFF for car in cars] as turn_signals
record initial [car.length for car in cars] as lengths
record initial [car.width for car in cars] as widths
