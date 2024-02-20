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
param map = f'/home/ak/Scenic/assets/maps/CARLA/{carla_map}.xodr'
model scenic.simulators.carla.model

param config = None
config = globalParameters.config

# import modules
from scenariogen.simulators.carla.behaviors import AutopilotFollowRoute
from scenariogen.simulators.carla.scenarios import ShowIntersectionScenario
from scenariogen.core.utils import route_from_turns

#--- Derived constants
intersection = network.elements[config['intersection']]

scenario ActorScenario():
  setup:
    route = route_from_turns(network, config['init_lane'], config['turns'])
    lanes = [network.elements[l] for l in route]
    centerline = PolylineRegion.unionAll([l.centerline for l in lanes])
    p0 = centerline.pointAlongBy(config['init_progress'])
    ego = Car at p0, facing roadDirection,
      with name f"{config['init_lane']}_{config['init_progress']}_{tuple(t.name for t in config['turns'])}",
      with physics True,
      with allowCollisions False,
      with behavior AutopilotFollowRoute(route=route,
                                        aggressiveness=config['aggressiveness'],
                                        use_rss=config['use_rss']),
      with blueprint config['blueprint'],
      with length config['length'],
      with width config['width'],
      with route route

scenario Main():
  compose:
    do ActorScenario(), \
        ShowIntersectionScenario(intersection)
