#--- Scenario parameters
description = """
  Several cars randomly pass through a 3way-stop intersection.
  """
param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.carla.model
param weather = 'CloudySunset'
param timestep = 0.05
param steps = 400
intersection_uid = 'intersection396'
max_nonegos = 10

#--- Python imports
import jsonpickle
import numpy as np
import random
import math
from scenic.core.regions import UnionRegion
from scenariogen.core.utils import turns_from_route
from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.core.utils import extend_lane_backward, extend_lane_forward
import random
from scenariogen.simulators.carla.behaviors import AutopilotRouteBehavior
from scenariogen.simulators.carla.utils import maneuverType_to_Autopilot_turn
from scenariogen.simulators.carla.behaviors import LeaderboardAgentBehavior

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

intersection = network.elements[intersection_uid]

config = {'description': description,
          'carla-map': carla_map,
          'map': globalParameters.map,
          'weather': globalParameters.weather,
          'timestep': globalParameters.timestep,
          'steps': globalParameters.steps,
          'intersection': intersection_uid,
          }

scenario SeedScenario():
  setup:
    min_route_length = 200
    min_distance_to_intersection = 20
    blueprint = 'vehicle.tesla.model3'

    lanes = [Uniform(*intersection.incomingLanes)]
    if lanes[0].centerline.length < min_distance_to_intersection:
      print('Incoming lane is too short, need to extend it backwards...')
      lanes = extend_lane_backward(lanes[0], min_distance_to_intersection - lanes[0].centerline.length, random)\
              + lanes
    route_length = sum(l.centerline.length for l in lanes)
    x0 = Range(1, route_length - min_distance_to_intersection)

    if route_length - x0 < min_route_length:
      lanes.extend(extend_lane_forward(lanes[-1], min_route_length-route_length+x0, random))

    route = tuple(l.uid for l in lanes)
    transform = CurvilinearTransform([p for lane in lanes
                                        for p in lane.centerline.lineString.coords
                                        ])
    y0 = 0
    h0 = 0
    p = transform.rectilinear(x0@y0, h0)
    p_end = transform.rectilinear(transform.axis.length@0, 0)

    agent = '/home/carla/carla_garage_fork/team_code/sensor_agent'
    agent_config = '/home/carla/carla_garage_fork/pretrained_models/leaderboard/tfpp_wp_all_0'
    track = 'SENSORS'
    keypoints = (p[0]@p[1], p_end[0]@p_end[1])
    ego_behavior = LeaderboardAgentBehavior(agent, agent_config, track, keypoints, debug=False)

    car = new Car at p[0]@p[1], facing p[2],
      with name 'ego',
      with rolename 'hero',
      with physics True,
      with allowCollisions False,
      with behavior ego_behavior,
      with blueprint blueprint,
      with length blueprint2dims[blueprint]['length'],
      with width blueprint2dims[blueprint]['width'],
      with color Color(0, 1, 0),
      with route route
    
    config['ego_blueprint'] = blueprint
    config['ego_route'] = route
    config['ego_init_progress_ratio'] = x0 / transform.axis.length

    nonego_config = {
      'auto_lane_change': False,
      'random_left_lanechange_percentage': 0,
      'random_right_lanechange_percentage': 0,
    }

    blueprints = tuple(blueprint2dims.keys())
    
    nonegos_count = DiscreteRange(1, max_nonegos)
    for i in range(nonegos_count):
      blueprint = Uniform(*blueprints)
      init_lane = Uniform(*intersection.incomingLanes, *intersection.outgoingLanes)
      x0 = Range(1, init_lane.centerline.length-3)
      ext = extend_lane_forward(init_lane, min_route_length - init_lane.centerline.length + x0, random)
      lanes = (init_lane,) + tuple(ext)
      turns = turns_from_route(lanes)
      route = tuple(l.uid for l in lanes)
      transform = CurvilinearTransform([p for lane in lanes
                                          for p in lane.centerline.lineString.coords
                                          ])
      y0 = 0
      h0 = 0
      p = transform.rectilinear((x0,y0), h0)
      name = f'{route[0]}_{int(x0)}'

      car = new Car at p[0]@p[1], facing p[2],
        with name name,
        with physics True,
        with allowCollisions False,
        with behavior AutopilotRouteBehavior(turns, config_override=nonego_config),
        with blueprint blueprint,
        with length blueprint2dims[blueprint]['length'],
        with width blueprint2dims[blueprint]['width'],
        with color Color(0, 0, 1),
        with route route

