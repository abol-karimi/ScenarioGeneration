#--- Python imports
import jsonpickle
import numpy as np
import random
from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType
from scenariogen.core.utils import route_from_turns

#--- Scenario parameters
description = """
  Several cars randomly pass through a 3way-stop intersection.
  """
param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/ak/Scenic/assets/maps/CARLA/{carla_map}.xodr'
model scenic.simulators.carla.model
from scenariogen.simulators.carla.behaviors import AutopilotFollowRoute

intersection_uid = 'intersection1930'
traffic_rules = '3way-T_stopOnAll.lp'
arrival_distance = 4
max_nonegos = 10

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

intersection = network.elements[intersection_uid]

config = {'carla-map': carla_map,
          'map': globalParameters.map,
          'intersection': intersection_uid,
          'traffic-rules': traffic_rules,
          'simulator': 'carla',
          }

scenario SeedScenario():
  setup:
    ego_maneuver = Uniform(*intersection.maneuvers)
    ego_lanes = (ego_maneuver.startLane, ego_maneuver.connectingLane, ego_maneuver.endLane)
    ego_init_progress_ratio = Range(0, 1)
    ego_route = tuple(l.uid for l in ego_lanes)
    ego_signal = SignalType.from_maneuver_type(ego_maneuver.type)
    ego_p0 = ego_maneuver.startLane.centerline.pointAlongBy(ego_maneuver.startLane.centerline.length*ego_init_progress_ratio)
    ego_blueprint = Uniform(*blueprint2dims.keys())
    car = new Car at ego_p0, facing roadDirection,
      with name 'ego',
      with physics True,
      with allowCollisions False,
      with behavior AutopilotFollowRoute(route=ego_route,
                                        aggressiveness='normal',
                                        use_rss=False),
      with blueprint ego_blueprint,
      with length blueprint2dims[ego_blueprint]['length'],
      with width blueprint2dims[ego_blueprint]['width'],
      with color Color(0, 1, 0),
      with route ego_route
    
    config['ego_route'] = ego_route
    config['ego_init_progress_ratio'] = ego_init_progress_ratio
    config['ego_blueprint'] = ego_blueprint
    config['ego_signal'] = ego_signal

    for i in range(DiscreteRange(1, max_nonegos)):
      init_lane = Uniform(*intersection.incomingLanes)
      maneuver = Uniform(*init_lane.maneuvers)
      lanes = (maneuver.startLane, maneuver.connectingLane, maneuver.endLane)
      centerline = PolylineRegion.unionAll([l.centerline for l in lanes])
      init_progress = Range(0, init_lane.centerline.length)
      route = tuple(l.uid for l in lanes)
      blueprint = Uniform(*blueprint2dims.keys())
      p0 = centerline.pointAlongBy(init_progress)
     
      car = new Car at p0, facing roadDirection,
        with name f'{route[0]}_{init_progress}_{maneuver.type}',
        with physics True,
        with allowCollisions False,
        with behavior AutopilotFollowRoute(route=route,
                                          aggressiveness=Uniform('cautious', 'normal'),
                                          use_rss=False),
        with blueprint blueprint,
        with length blueprint2dims[blueprint]['length'],
        with width blueprint2dims[blueprint]['width'],
        with color Color(0, 0, 1),
        with route route
