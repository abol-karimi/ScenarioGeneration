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
model scenic.simulators.carla.model
param weather = 'CloudySunset'
param timestep = 0.1
param steps = 200
intersection_uid = 'intersection1930'

from scenic.domains.driving.roads import ManeuverType
ego_blueprint = 'vehicle.tesla.model3'
ego_init_lane = 'road9_lane1'
ego_turns = (ManeuverType.LEFT_TURN,)
ego_init_progress_ratio = .1

major_init_lane = 'road24_lane0'
major_turns = (ManeuverType.STRAIGHT,)
major_init_progress_ratio = .7

minor_init_lane = 'road3_lane1'
minor_turns = (ManeuverType.LEFT_TURN,)
minor_init_progress_ratio = .1

#--- Python imports
import jsonpickle
from scenariogen.core.utils import route_from_turns
from scenariogen.simulators.carla.behaviors import BehaviorAgentReachDestination

# Derived constants
ego_route = route_from_turns(network, ego_init_lane, ego_turns)

major_route = route_from_turns(network, major_init_lane, major_turns)
major_lanes = [network.elements[uid] for uid in major_route]
major_polyline = PolylineRegion.unionAll([l.centerline for l in major_lanes])
major_p0 = major_polyline.pointAlongBy(major_init_progress_ratio*major_polyline.length)

minor_route = route_from_turns(network, minor_init_lane, minor_turns)
minor_lanes = [network.elements[uid] for uid in minor_route]
minor_polyline = PolylineRegion.unionAll([l.centerline for l in minor_lanes])
minor_p0 = minor_polyline.pointAlongBy(minor_init_progress_ratio*minor_polyline.length)

intersection = network.elements[intersection_uid]

config = {'description': description,
          'carla_map': globalParameters.carla_map,
          'map': globalParameters.map,
          'weather': globalParameters.weather,
          'timestep': globalParameters.timestep,
          'steps': globalParameters.steps,
          'intersection': intersection_uid,
          'ego_blueprint': ego_blueprint,
          'ego_route': ego_route,
          'ego_init_progress_ratio': ego_init_progress_ratio
          }

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      blueprints = jsonpickle.decode(f.read())

    major_car = new Car at major_p0, facing roadDirection,
      with name 'nonego_major',
      with route major_route,
      with physics True,
      with allowCollisions False,
      with behavior BehaviorAgentReachDestination(major_route),
      with length blueprints['vehicle.tesla.model3']['length'],
      with width blueprints['vehicle.tesla.model3']['width']

    minor_car = new Car at minor_p0, facing roadDirection,
      with name 'nonego_minor',
      with route minor_route,
      with physics True,
      with allowCollisions False,
      with behavior BehaviorAgentReachDestination(minor_route),
      with length blueprints['vehicle.ford.crown']['length'],
      with width blueprints['vehicle.ford.crown']['width']