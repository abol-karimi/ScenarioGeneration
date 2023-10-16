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

from scenic.domains.driving.roads import ManeuverType
ego_blueprint = 'vehicle.tesla.model3'
ego_init_lane = 'road9_lane2'
ego_turns = (ManeuverType.LEFT_TURN,)
ego_init_progress_ratio = .35

left_init_lane = 'road44_lane1'
left_turns = (ManeuverType.LEFT_TURN,)

right_init_lane = 'road8_lane1'
right_turns = (ManeuverType.STRAIGHT,)

#--- Python imports
import jsonpickle
import numpy as np
from scenariogen.core.utils import route_from_turns
from scenariogen.simulators.carla.behaviors import AutopilotPathBehavior, AutopilotRouteBehavior
from scenariogen.core.geometry import CurvilinearTransform

#--- Derived constants
with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

ego_route = route_from_turns(network, ego_init_lane, ego_turns)

waypoints_separation = 1

left_blueprint = 'vehicle.tesla.model3'
left_car_length = blueprint2dims[left_blueprint]['length']
left_car_width = blueprint2dims[left_blueprint]['width']
left_route = route_from_turns(network, left_init_lane, left_turns)
left_lanes = [network.elements[l] for l in left_route]
left_polyline = PolylineRegion.unionAll([l.centerline for l in left_lanes])
left_transform = CurvilinearTransform([p for lane in left_lanes
                                    for p in lane.centerline.lineString.coords
                                    ])
x0 = left_lanes[0].centerline.length - 5
y0 = 0
h0 = 0
left_p0 = left_transform.rectilinear(x0@y0, h0)
left_waypoints = [Vector(*left_transform.rectilinear(x@0))
                  for x in np.arange(x0+left_car_length+waypoints_separation, left_transform.axis.length, waypoints_separation)]


right_blueprint = 'vehicle.ford.crown'
right_car_length = blueprint2dims[right_blueprint]['length']
right_car_width = blueprint2dims[right_blueprint]['width']
right_route = route_from_turns(network, right_init_lane, right_turns)
right_lanes = [network.elements[l] for l in right_route]
right_polyline = PolylineRegion.unionAll([l.centerline for l in right_lanes])
right_transform = CurvilinearTransform([p for lane in right_lanes
                                    for p in lane.centerline.lineString.coords
                                    ])
x0 = right_lanes[0].centerline.length - 2
y0 = 0
h0 = 0
right_p0 = right_transform.rectilinear(x0@y0, h0)
right_waypoints = [Vector(*right_transform.rectilinear(x@0))
                    for x in np.arange(x0+right_car_length+waypoints_separation, right_transform.axis.length, waypoints_separation)]

intersection = network.elements[intersection_uid]

config = {'description': description,
          'carla_map': carla_map,
          'map': globalParameters.map,
          'weather': globalParameters.weather,
          'timestep': globalParameters.timestep,
          'steps': globalParameters.steps,
          'compatible_simulators': ('carla',),
          'intersection': intersection_uid,
          'ego_blueprint': ego_blueprint,
          'ego_route': ego_route,
          'ego_init_progress_ratio': ego_init_progress_ratio
          }

scenario SeedScenario():
  setup:

    left_car = new Car at left_p0, facing left_p0[2],
      with name 'nonego_left',
      with route left_route,
      with physics True,
      with allowCollisions False,
      with behavior AutopilotRouteBehavior(maneuvers=left_turns),
      with blueprint left_blueprint,
      with length blueprint2dims['vehicle.tesla.model3']['length'],
      with width blueprint2dims['vehicle.tesla.model3']['width']

    right_car = new Car at right_p0, facing right_p0[2],
      with name 'nonego_right',
      with route right_route,
      with physics True,
      with allowCollisions False,
      with behavior AutopilotRouteBehavior(maneuvers=right_turns),
      with blueprint right_blueprint,
      with length right_car_length,
      with width right_car_width
