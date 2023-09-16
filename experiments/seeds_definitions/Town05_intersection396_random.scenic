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
duration_seconds = 20
intersection_uid = 'intersection396'
traffic_rules = '4way-uncontrolled.lp'
arrival_distance = 4
max_nonegos = 10

#--- Python imports
import jsonpickle
import numpy as np
import random
import math
from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType
from scenariogen.core.utils import route_from_turns
from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.core.utils import extend_lane_backward
import random
from scenariogen.simulators.carla.behaviors import AutopilotFollowWaypoints

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

intersection = network.elements[intersection_uid]

config = {'carla_map': carla_map,
          'map': globalParameters.map,
          'weather': globalParameters.weather,
          'intersection': intersection_uid,
          'traffic_rules': traffic_rules,
          'simulator': 'carla',
          'timestep': globalParameters.timestep,
          'steps': int(duration_seconds/globalParameters.timestep)
          }

scenario SeedScenario():
  setup:
    blueprints = tuple(blueprint2dims.keys())
    min_distance_to_intersection = 0
    blueprint = Uniform(*blueprints)
    init_progress_ratio = Range(0, 0.5)
    maneuver = Uniform(*intersection.maneuvers)
    signal = SignalType.from_maneuver_type(maneuver.type)
    lanes = (maneuver.startLane, maneuver.connectingLane, maneuver.endLane)
    init_lanes_length = maneuver.startLane.centerline.length
    if maneuver.startLane.centerline.length < min_distance_to_intersection:    
      ext = extend_lane_backward(maneuver.startLane, min_distance_to_intersection - maneuver.startLane.centerline.length, random)
      lanes = ext + (maneuver.startLane, maneuver.connectingLane, maneuver.endLane)
      init_lanes_length += sum(l.centerline.length for l in ext)
    route = tuple(l.uid for l in lanes)
    transform = CurvilinearTransform([p for lane in lanes
                                        for p in lane.centerline.lineString.coords
                                        ])
    x0 = init_lanes_length * init_progress_ratio
    y0 = 0
    h0 = 0
    p = transform.rectilinear(x0@y0, h0)
    waypoints_separation = 50
    waypoints = (Vector(*transform.rectilinear(x@0))
                 for x in np.arange(x0+waypoints_separation, init_lanes_length, waypoints_separation))
    car = new Car at p[0]@p[1], facing p[2],
      with name 'ego',
      with physics True,
      with allowCollisions False,
      with behavior AutopilotFollowWaypoints(waypoints=waypoints,
                                        aggressiveness='normal',
                                        use_rss=False),
      with blueprint blueprint,
      with length blueprint2dims[blueprint]['length'],
      with width blueprint2dims[blueprint]['width'],
      with color Color(0, 1, 0),
      with route route,
      with signal signal
    
    config['ego_route'] = route
    config['ego_init_progress_ratio'] = init_progress_ratio
    config['ego_blueprint'] = blueprint
    config['ego_signal'] = signal

    init_progress_ratio = Range(0, .9)
    for i in range(DiscreteRange(1, max_nonegos)):
      blueprint = Uniform(*blueprints)
      maneuver = Uniform(*intersection.maneuvers)
      signal = SignalType.from_maneuver_type(maneuver.type)
      lanes = (maneuver.startLane, maneuver.connectingLane, maneuver.endLane)
      if maneuver.startLane.centerline.length < min_distance_to_intersection:
        ext = extend_lane_backward(maneuver.startLane, min_distance_to_intersection - maneuver.startLane.centerline.length, random)
        lanes = ext + lanes
      route = tuple(l.uid for l in lanes)
      transform = CurvilinearTransform([p for lane in lanes
                                          for p in lane.centerline.lineString.coords
                                          ])
      x0 = transform.axis.length * init_progress_ratio
      y0 = 0
      h0 = 0
      p = transform.rectilinear(x0@y0, h0)
      waypoints = (Vector(*transform.rectilinear(x@0))
                   for x in np.arange(x0+waypoints_separation, transform.axis.length, waypoints_separation))
      car = new Car at p[0]@p[1], facing p[2],
        with name f'{route[0]}_{(x0,y0,h0)}_{maneuver.type.name}',
        with physics True,
        with allowCollisions False,
        with behavior AutopilotFollowWaypoints(waypoints=waypoints,
                                          aggressiveness=Uniform('cautious', 'normal'),
                                          use_rss=False),
        with blueprint blueprint,
        with length blueprint2dims[blueprint]['length'],
        with width blueprint2dims[blueprint]['width'],
        with color Color(0, 0, 1),
        with route route,
        with signal SignalType.from_maneuver_type(maneuver.type)
