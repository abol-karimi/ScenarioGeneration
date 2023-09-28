#--- Scenario parameters
description = """
  Two cars arrive at a 3way-stop T-intersection about the same time.
  One car arrives from the minor road and turns left.
  The other car arrives from the major road on the left side of the first car, and drives straight throught the intersection.
  VUT is intended to start on the major road, on the right side of the first car, and to make a left turn to the minor road.
  """

param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.newtonian.driving_model
param weather = 'CloudySunset'
param timestep = 0.1
param steps = 200
intersection_uid = 'intersection1930'
traffic_rules = '3way-T_stopOnAll.lp'
arrival_distance = 4

#--- Python imports
import jsonpickle
import importlib
from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType
from scenariogen.core.utils import route_from_turns
from scenariogen.simulators.newtonian.behaviors import FourWayStopBehavior

ego_init_lane = 'road9_lane1'
ego_turns = (ManeuverType.LEFT_TURN,)
ego_init_progress_ratio = .4
ego_blueprint = 'vehicle.dodge.charger_2020'

major_init_lane = 'road24_lane0'
major_turns = (ManeuverType.STRAIGHT,)
major_init_progress = 70
major_signal = SignalType.OFF
major_blueprint = 'vehicle.tesla.model3'

minor_init_lane = 'road3_lane1'
minor_turns = (ManeuverType.LEFT_TURN,)
minor_init_progress = 10
minor_signal = SignalType.LEFT
minor_blueprint = 'vehicle.ford.mustang'

# Derived constants
ego_route = route_from_turns(network, ego_init_lane, ego_turns)
ego_lanes = [network.elements[uid] for uid in ego_route]
ego_polyline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
ego_p0 = ego_polyline.pointAlongBy(ego_init_progress_ratio*ego_polyline.length)
ego_signal = SignalType.LEFT

major_route = route_from_turns(network, major_init_lane, major_turns)
major_lanes = [network.elements[uid] for uid in major_route]
major_polyline = PolylineRegion.unionAll([l.centerline for l in major_lanes])
major_p0 = major_polyline.pointAlongBy(major_init_progress)

minor_route = route_from_turns(network, minor_init_lane, minor_turns)
minor_lanes = [network.elements[uid] for uid in minor_route]
minor_polyline = PolylineRegion.unionAll([l.centerline for l in minor_lanes])
minor_p0 = minor_polyline.pointAlongBy(minor_init_progress)

intersection = network.elements[intersection_uid]

config = {'description': description,
          'carla_map': globalParameters.carla_map,
          'map': globalParameters.map,
          'weather': globalParameters.weather,
          'timestep': globalParameters.timestep,
          'steps': globalParameters.steps,
          'compatible_simulators': ('newtonian',),
          'intersection': intersection_uid,
          'traffic_rules': traffic_rules,
          'ego_blueprint': ego_blueprint,
          'ego_route': ego_route,
          'ego_init_progress_ratio': ego_init_progress_ratio,
          }

ego_module = importlib.import_module('experiments.agents.followRouteAvoidCollisions')
ego_scenario = ego_module.EgoScenario(config)

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      blueprint2dims = jsonpickle.decode(f.read())
    
    major_car = new Car at major_p0, facing roadDirection,
      with name 'nonego_major',
      with blueprint major_blueprint,
      with route major_route,
      with physics True,
      with allowCollisions False,
      with signal major_signal,
      with behavior FourWayStopBehavior(major_lanes, target_speed=6, arrival_distance=5),
      with length blueprint2dims[major_blueprint]['length'],
      with width blueprint2dims[major_blueprint]['width']

    minor_car = new Car at minor_p0, facing roadDirection,
      with name 'nonego_minor',
      with blueprint minor_blueprint,
      with route minor_route,
      with physics True,
      with allowCollisions False,
      with signal minor_signal,
      with behavior FourWayStopBehavior(minor_lanes, target_speed=6, arrival_distance=5),
      with length blueprint2dims[minor_blueprint]['length'],
      with width blueprint2dims[minor_blueprint]['width']
  
  compose:
    do ego_scenario