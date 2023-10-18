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
param steps = 200
intersection_uid = 'intersection396'
arrival_distance = 4

from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType
ego_blueprint = 'vehicle.tesla.model3'
ego_init_lane = 'road9_lane2'
ego_turns = (ManeuverType.LEFT_TURN,)
ego_init_progress_ratio = .1

left_blueprint = 'vehicle.ford.crown'
left_init_lane = 'road44_lane1'
left_turns = (ManeuverType.STRAIGHT,)
left_signal = SignalType.OFF

right_blueprint = 'vehicle.ford.crown'
right_init_lane = 'road8_lane1'
right_turns = (ManeuverType.STRAIGHT,)
right_signal = SignalType.OFF

#--- Python imports
import jsonpickle
import numpy as np
from scenariogen.core.utils import route_from_turns
from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.simulators.carla.behaviors import AutopilotRouteBehavior
from experiments.agents.configs import VUT_config

#--- Derived constants
ego_route = route_from_turns(network, ego_init_lane, ego_turns)

waypoints_separation = 50

left_route = route_from_turns(network, left_init_lane, left_turns)
left_lanes = [network.elements[l] for l in left_route]
left_polyline = PolylineRegion.unionAll([l.centerline for l in left_lanes])
transform = CurvilinearTransform([p for lane in left_lanes
                                    for p in lane.centerline.lineString.coords
                                    ])
x0 = left_lanes[0].centerline.length - 20
y0 = 0
h0 = 0
left_p0 = transform.rectilinear(x0@y0, h0)
left_waypoints = (Vector(*transform.rectilinear(x@0))
              for x in np.arange(x0+waypoints_separation, transform.axis.length, waypoints_separation))


right_route = route_from_turns(network, right_init_lane, right_turns)
right_lanes = [network.elements[l] for l in right_route]
right_polyline = PolylineRegion.unionAll([l.centerline for l in right_lanes])
transform = CurvilinearTransform([p for lane in right_lanes
                                    for p in lane.centerline.lineString.coords
                                    ])
x0 = right_lanes[0].centerline.length - 20
y0 = 0
h0 = 0
right_p0 = transform.rectilinear(x0@y0, h0)
right_waypoints = (Vector(*transform.rectilinear(x@0))
              for x in np.arange(x0+waypoints_separation, transform.axis.length, waypoints_separation))


intersection = network.elements[intersection_uid]

config = {'description': description,
          'carla_map': carla_map,
          'map': globalParameters.map,
          'weather': globalParameters.weather,
          'compatible_simulators': ('carla',),
          'timestep': globalParameters.timestep,
          'steps': globalParameters.steps,
          'intersection': intersection_uid,
          'ego_blueprint': ego_blueprint,
          'ego_route': ego_route,
          'ego_init_progress_ratio': ego_init_progress_ratio,
          }
behavior StopAtArrival():
  do AutopilotRouteBehavior([ManeuverType.STRAIGHT], config_override=VUT_config) # until (distance from (front of self) to intersection) < arrival_distance
  take SetAutopilotAction(False), SetThrottleAction(0), SetBrakeAction(1)

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      blueprints = jsonpickle.decode(f.read())

    left_car = new Car at left_p0, facing left_p0[2],
      with name 'nonego_left',
      with route left_route,
      with physics True,
      with allowCollisions False,
      with behavior AutopilotRouteBehavior(left_turns,
                                           config_override={**VUT_config, 'ignore_signs_percentage': 100}),
      with blueprint left_blueprint,
      with length blueprints[left_blueprint]['length'],
      with width blueprints[left_blueprint]['width']
    
    right_car = new Car at right_p0, facing right_p0[2],
      with name 'nonego_right',
      with route right_route,
      with physics True,
      with allowCollisions False,
      with behavior AutopilotRouteBehavior(right_turns, config_override=VUT_config),
      with blueprint right_blueprint,
      with length blueprints[right_blueprint]['length'],
      with width blueprints[right_blueprint]['width']
