# Scenic parameters
model scenic.simulators.carla.model

# imports
from scenariogen.simulators.carla.behaviors import AutopilotReachDestination
from scenariogen.core.signals import SignalType
import jsonpickle

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

scenario EgoScenario(config):
  setup:
    config_with_defaults = {'aggressiveness': 'normal',
                            'use_rss': False,
                            'ego_signal': SignalType.OFF,
                            **config}
    ego_lanes = [network.elements[l] for l in config_with_defaults['ego_route']]
    ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
    ego_init_pos = ego_centerline.pointAlongBy(config_with_defaults['ego_init_progress_ratio']*ego_centerline.length)
    ego_blueprint = config_with_defaults['ego_blueprint']
    ego = new Car at ego_init_pos,
      with name 'ego',
      with color Color(0, 1, 0),
      with blueprint config_with_defaults['ego_blueprint'],
      with width blueprint2dims[ego_blueprint]['width'],
      with length blueprint2dims[ego_blueprint]['length'],
      with signal config_with_defaults['ego_signal'],
      with behavior AutopilotReachDestination(route=config_with_defaults['ego_route'],
                                        aggressiveness=config_with_defaults['aggressiveness'],
                                        use_rss=config_with_defaults['use_rss']),
      with physics True,
      with allowCollisions False