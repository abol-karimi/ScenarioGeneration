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
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.carla.model
from scenariogen.simulators.carla.behaviors import AutopilotFollowRoute

intersection_uid = 'intersection1930'
traffic_rules = '3way-T_stopOnAll.lp'
arrival_distance = 4
max_nonegos = 10

#--- Derived constants
num_nonegos = DiscreteRange(1, max_nonegos)
intersection = network.elements[intersection_uid]
config = {'carla_map': carla_map,
          'map': globalParameters.map,
          'intersection': intersection_uid,
          'traffic_rules': traffic_rules,
          }

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      blueprint2dims = jsonpickle.decode(f.read())
    
    for i in range(1+num_nonegos):
      init_lane = Uniform(*intersection.incomingLanes)
      maneuver = Uniform(*init_lane.maneuvers)
      lanes = tuple(maneuver.startLane, maneuver.connectingLane, maneuver.endLane)
      centerline = PolylineRegion.unionAll([l.centerline for l in lanes])
      init_progress = Range(0, centerline.length)
      route = tuple(l.uid for l in lanes)

      blueprint = Uniform(tuple(blueprint2dims.keys()))

      p0 = centerline.pointAlongBy(init_progress)

      car = Car at p0, facing roadDirection,
        with name f'{route[0]}_{init_progress}_{maneuver.type}' if i > 0 else 'ego',
        with physics True,
        with allowCollisions False,
        with behavior AutopilotFollowRoute(route=route,
                                          aggressiveness=Uniform('cautious', 'normal', 'aggressive'),
                                          rss_enabled=Uniform(True, False)),
        with length blueprint2dims[blueprint]['length'],
        with width blueprint2dims[blueprint]['width'],
        with route route,
        with signal SignalType.from_maneuver_type(maneuver.type)