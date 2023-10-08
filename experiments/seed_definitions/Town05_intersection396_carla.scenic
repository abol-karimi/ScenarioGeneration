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
ego_init_progress_ratio = .1

left_init_lane = 'road44_lane1'
left_turns = (ManeuverType.LEFT_TURN,)
left_init_progress_ratio = .2

right_init_lane = 'road8_lane1'
right_turns = (ManeuverType.STRAIGHT,)
right_init_progress_ratio = .1

#--- Python imports
import jsonpickle
import numpy as np
from scenariogen.core.utils import route_from_turns
from scenariogen.simulators.carla.behaviors import AutopilotReachDestination
from scenariogen.core.geometry import CurvilinearTransform

#--- Derived constants
ego_route = route_from_turns(network, ego_init_lane, ego_turns)

waypoints_separation = 50

left_route = route_from_turns(network, left_init_lane, left_turns)
left_lanes = [network.elements[l] for l in left_route]
left_polyline = PolylineRegion.unionAll([l.centerline for l in left_lanes])
transform = CurvilinearTransform([p for lane in left_lanes
                                    for p in lane.centerline.lineString.coords
                                    ])
x0 = transform.axis.length * left_init_progress_ratio
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
x0 = transform.axis.length * right_init_progress_ratio
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
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      blueprints = jsonpickle.decode(f.read())

    left_car = new Car at left_p0, facing left_p0[2],
      with name 'nonego_left',
      with route left_route,
      with physics True,
      with allowCollisions False,
      with behavior AutopilotReachDestination(route=left_route),
      with blueprint 'vehicle.tesla.model3',
      with length blueprints['vehicle.tesla.model3']['length'],
      with width blueprints['vehicle.tesla.model3']['width']

    right_car = new Car at right_p0, facing right_p0[2],
      with name 'nonego_right',
      with route right_route,
      with physics True,
      with allowCollisions False,
      with behavior AutopilotReachDestination(route=right_route),
      with blueprint 'vehicle.ford.crown',
      with length blueprints['vehicle.ford.crown']['length'],
      with width blueprints['vehicle.ford.crown']['width']
