""" Scenario Description
Two non-egos arrive at the intersection simultaneously,
	one is to the right of the other,
	and they both proceed simultaneously.
"""

#--- Scenic parameters
param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.domains.driving.model

#--- Python imports
import jsonpickle
from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType
from scenariogen.core.utils import route_from_turns

#--- Constants
intersection_uid = 'intersection396'
traffic_rules = '4way-uncontrolled.lp'
arrival_distance = 4
ego_init_lane = 'road9_lane2'
ego_turns = (ManeuverType.LEFT_TURN,)
ego_init_progress_ratio = 90

left_init_lane = 'road44_lane1'
left_turns = (ManeuverType.STRAIGHT,)
left_init_progress = 15
left_signal = SignalType.OFF

right_init_lane = 'road8_lane1'
right_turns = (ManeuverType.STRAIGHT,)
right_init_progress = 10
right_signal = SignalType.OFF

#--- Derived constants
ego_route = route_from_turns(network, ego_init_lane, ego_turns)

left_route = route_from_turns(network, left_init_lane, left_turns)
left_lanes = [network.elements[l] for l in left_route]
left_polyline = PolylineRegion.unionAll([l.centerline for l in left_lanes])
left_p0 = left_polyline.pointAlongBy(left_init_progress)

right_route = route_from_turns(network, right_init_lane, right_turns)
right_lanes = [network.elements[l] for l in right_route]
right_polyline = PolylineRegion.unionAll([l.centerline for l in right_lanes])
right_p0 = right_polyline.pointAlongBy(right_init_progress)

intersection = network.elements[intersection_uid]
param config = {'carla_map': carla_map,
                'map': globalParameters.map,
                'intersection': intersection_uid,
                'traffic_rules': traffic_rules,
                'ego_route': ego_route,
                'ego_init_progress_ratio': ego_init_progress_ratio}

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
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

    left_car = Car at left_p0, facing roadDirection,
      with name 'nonego_left',
      with route left_route,
      with physics True,
      with allowCollisions False,
      with signal left_signal,
      with behavior PassBehavior(4, left_lanes),
      with length blueprints['vehicle.tesla.model3']['length'],
      with width blueprints['vehicle.tesla.model3']['width']

    right_car = Car at right_p0, facing roadDirection,
      with name 'nonego_right',
      with route right_route,
      with physics True,
      with allowCollisions False,
      with signal right_signal,
      with behavior PassBehavior(4, right_lanes),
      with length blueprints['vehicle.ford.crown']['length'],
      with width blueprints['vehicle.ford.crown']['width']
    
    cars = [left_car, right_car]