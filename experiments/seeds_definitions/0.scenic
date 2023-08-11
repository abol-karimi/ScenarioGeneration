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

#--- Python imports
import jsonpickle
from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType
from scenariogen.core.utils import route_from_turns

intersection_uid = 'intersection1930'
traffic_rules = '3way-T_stopOnAll.lp'
arrival_distance = 4
ego_init_lane = 'road9_lane1'
ego_turns = (ManeuverType.LEFT_TURN,)
ego_init_progress = 40

major_init_lane = 'road24_lane0'
major_turns = (ManeuverType.STRAIGHT,)
major_init_progress = 70
major_signal = SignalType.OFF

minor_init_lane = 'road3_lane1'
minor_turns = (ManeuverType.LEFT_TURN,)
minor_init_progress = 10
minor_signal = SignalType.LEFT

# Derived constants
ego_route = route_from_turns(network, ego_init_lane, ego_turns)

major_route = route_from_turns(network, major_init_lane, major_turns)
major_lanes = [network.elements[l] for l in major_route]
major_polyline = PolylineRegion.unionAll([l.centerline for l in major_lanes])
major_p0 = major_polyline.pointAlongBy(major_init_progress)

minor_route = route_from_turns(network, minor_init_lane, minor_turns)
minor_lanes = [network.elements[l] for l in minor_route]
minor_polyline = PolylineRegion.unionAll([l.centerline for l in minor_lanes])
minor_p0 = minor_polyline.pointAlongBy(minor_init_progress)

intersection = network.elements[intersection_uid]

param config = {'description': description,
                'carla_map': globalParameters.carla_map,
                'map': globalParameters.map,
                'intersection': intersection_uid,
                'traffic_rules': traffic_rules,
                'ego_route': ego_route,
                'ego_init_progress': ego_init_progress
                }

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint_library.json', 'r') as f:
      blueprints = jsonpickle.decode(f.read())

    behavior StopBehavior():
      take SetThrottleAction(0)
      take SetBrakeAction(1)
      while True:
        wait

    behavior PassBehavior(speed, trajectory):
      do FollowTrajectoryBehavior(speed, trajectory) until (distance from (front of self) to intersection) <= arrival_distance
      do StopBehavior() until self.speed <= 0.1
      do FollowTrajectoryBehavior(speed, trajectory)
      do FollowLaneBehavior(speed)

    major_car = Car at major_p0, facing roadDirection,
      with name 'nonego_major',
      with route major_route,
      with physics True,
      with allowCollisions False,
      with signal major_signal,
      with behavior PassBehavior(4, major_lanes),
      with length blueprints['vehicle.tesla.model3']['length'],
      with width blueprints['vehicle.tesla.model3']['width']

    minor_car = Car at minor_p0, facing roadDirection,
      with name 'nonego_minor',
      with route minor_route,
      with physics True,
      with allowCollisions False,
      with signal minor_signal,
      with behavior PassBehavior(4, minor_lanes),
      with length blueprints['vehicle.ford.crown']['length'],
      with width blueprints['vehicle.ford.crown']['width']

    cars = [major_car, minor_car]