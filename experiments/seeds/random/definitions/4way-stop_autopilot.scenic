#--- Scenario parameters
description = """
  Several cars randomly pass through a 3way-stop intersection.
  """
param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.carla.model
param weather = 'CloudySunset'
param timestep = 0.1
param steps = 200
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
from experiments.agents.configs import VUT_config

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

intersection = network.elements[intersection_uid]

config = {'description': description,
          'carla_map': carla_map,
          'map': globalParameters.map,
          'weather': globalParameters.weather,
          'timestep': globalParameters.timestep,
          'steps': globalParameters.steps,
          'intersection': intersection_uid,
          }

monitor CheckOnRoute(car, route_lanes):
  region = UnionRegion(*route_lanes)
  while True:
    if not car.position in region:
      print(f'Car {car.name} is off route at time step {simulation().currentTime}')
    wait

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
    car = new Car at p[0]@p[1], facing p[2],
      with name 'ego',
      with physics True,
      with allowCollisions False,
      with behavior AutopilotRouteBehavior(turns_from_route(lanes), config_override=VUT_config),
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
    for i in range(DiscreteRange(1, max_nonegos)):
      blueprint = Uniform(*blueprints)
      init_lane = Uniform(*intersection.incomingLanes, *intersection.outgoingLanes)
      x0 = Uniform(1, init_lane.centerline.length-3)
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
      name = f'{route[0]}_{x0}_' + '_'.join(map(str, tuple(maneuverType_to_Autopilot_turn(m) for m in turns)))

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
      
      require monitor CheckOnRoute(car, lanes)
