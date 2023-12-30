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
param timestep = 0.05
param steps = 400
intersection_uid = 'intersection396'
arrival_distance = 4

from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType
ego_blueprint = 'vehicle.tesla.model3'
ego_init_lane = 'road9_lane2'
ego_turns = (ManeuverType.LEFT_TURN,)
ego_init_progress_ratio = .3

#--- Python imports
import jsonpickle
import numpy as np
from scenariogen.core.utils import route_from_turns
from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.simulators.carla.behaviors import AutopilotRouteBehavior
from experiments.agents.configs import VUT_config

#--- Derived constants
ego_route = route_from_turns(network, ego_init_lane, ego_turns)

intersection = network.elements[intersection_uid]

config = {'description': description,
          'carla_map': carla_map,
          'map': globalParameters.map,
          'weather': globalParameters.weather,
          'timestep': globalParameters.timestep,
          'steps': globalParameters.steps,
          'intersection': intersection_uid,
          'ego_blueprint': ego_blueprint,
          'ego_route': ego_route,
          'ego_init_progress_ratio': ego_init_progress_ratio,
          }

scenario SeedScenario():
  setup:
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      blueprints = jsonpickle.decode(f.read())

