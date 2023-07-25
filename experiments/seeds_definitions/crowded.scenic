#--- Python imports
import jsonpickle
import numpy as np
import random
from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType
from scenariogen.core.utils import route_from_turns

#--- Scenario parameters
description = """
  Several cars pass through a 4way-uncontrolled intersection.
  VUT is intended to make an unprotected left turn.
  """
param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.carla.model
from scenariogen.simulators.carla.behaviors import AutopilotFollowRoute

intersection_uid = 'intersection396'
traffic_rules = '4way-uncontrolled.lp'
arrival_distance = 4
ego_init_lane = 'road9_lane2'
ego_turns = (ManeuverType.LEFT_TURN,)
ego_init_progress = 30

#--- Derived constants
intersection = network.elements[intersection_uid]
param config = {'carla_map': carla_map,
                'map': globalParameters.map,
                'intersection': intersection_uid,
                'traffic_rules': traffic_rules,
                'ego_route': route_from_turns(network, ego_init_lane, ego_turns),
                'ego_init_progress': ego_init_progress
                }

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint_library.json', 'r') as f:
      car_blueprints = jsonpickle.decode(f.read())

    for lane in intersection.incomingLanes:
      distances = list(np.arange(random.uniform(0, 2),
                                  lane.centerline.length - random.uniform(4, 10),
                                  random.uniform(10, 30)))
      spawn_points = [lane.centerline.pointAlongBy(d)
                      for d in distances]
      maneuvers = random.choices(lane.maneuvers, k=len(spawn_points))
      routes_lanes = ([m.startLane, m.connectingLane, m.endLane]
                for m in maneuvers)
      routes = ((m.startLane.uid, m.connectingLane.uid, m.endLane.uid)
                for m in maneuvers)
      turns = (m.type for m in maneuvers)
      blueprints = random.choices(tuple(car_blueprints.keys()), k=len(spawn_points))
      for r, p, d, t, m, b in zip(routes, spawn_points, distances, turns, maneuvers, blueprints):
        car = Car at p, facing roadDirection,
          with name f'{r[0]}_{d}_{t}',
          with physics True,
          with allowCollisions False,
          with behavior AutopilotFollowRoute(route=r,
                                            aggressiveness='cautious',
                                            rss_enabled=False),
          with length car_blueprints[b]['length'],
          with width car_blueprints[b]['width'],
          with route tuple(r),
          with signal SignalType.from_maneuver(m)