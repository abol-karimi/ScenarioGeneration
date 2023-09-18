#--- Scenario parameters
description = """
Two non-egos arrive at the intersection simultaneously,
	one is to the right of the other,
	and they both proceed simultaneously.
"""
param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.carla.model
param weather = 'CloudySunset'
param timestep = 0.1
duration_seconds = 20
intersection_uid = 'intersection396'
traffic_rules = '4way-uncontrolled.lp'
arrival_distance = 4

from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType
ego_blueprint = 'vehicle.tesla.model3'
ego_init_lane = 'road9_lane2'
ego_turns = (ManeuverType.LEFT_TURN,)
ego_init_progress_ratio = .5

left_init_lane = 'road44_lane1'
left_turns = (ManeuverType.STRAIGHT,)
left_init_progress = 15
left_signal = SignalType.OFF

right_init_lane = 'road8_lane1'
right_turns = (ManeuverType.STRAIGHT,)
right_init_progress = 10
right_signal = SignalType.OFF

#--- Python imports
import jsonpickle
from scenariogen.core.utils import route_from_turns
from scenariogen.simulators.carla.behaviors import AutopilotFollowRoute

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

config = {'carla_map': carla_map,
          'map': globalParameters.map,
          'weather': globalParameters.weather,
          'compatible_simulators': ('carla'),
          'timestep': globalParameters.timestep,
          'steps': int(duration_seconds/globalParameters.timestep),          
          'intersection': intersection_uid,
          'traffic_rules': traffic_rules,
          'ego_blueprint': ego_blueprint,
          'ego_route': ego_route,
          'ego_init_progress_ratio': ego_init_progress_ratio}

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      blueprints = jsonpickle.decode(f.read())

    left_car = new Car at left_p0, facing roadDirection,
      with name 'nonego_left',
      with route left_route,
      with physics True,
      with allowCollisions False,
      with signal left_signal,
      with behavior AutopilotFollowRoute(route=left_route,
                                        aggressiveness='normal',
                                        use_rss=False),
      with blueprint 'vehicle.tesla.model3',
      with length blueprints['vehicle.tesla.model3']['length'],
      with width blueprints['vehicle.tesla.model3']['width']

    right_car = new Car at right_p0, facing roadDirection,
      with name 'nonego_right',
      with route right_route,
      with physics True,
      with allowCollisions False,
      with signal right_signal,
      with behavior AutopilotFollowRoute(route=right_route,
                                        aggressiveness='normal',
                                        use_rss=False),
      with blueprint 'vehicle.ford.crown',
      with length blueprints['vehicle.ford.crown']['length'],
      with width blueprints['vehicle.ford.crown']['width']
