# Scenic parameters
model scenic.simulators.carla.model

# imports
import jsonpickle
from scenariogen.core.signals import SignalType
from scenariogen.core.utils import turns_from_route
from scenariogen.simulators.carla.behaviors import AutopilotRouteBehavior
from experiments.agents.configs import VUT_config


with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

scenario EgoScenario(config):
  setup:
    if config['simulator'] != 'carla':
      raise ValueError(f"autopilot is not compatible with the {config['simulator']} simulator!")

    lanes = [network.elements[l] for l in config['ego_route']]
    centerline = PolylineRegion.unionAll([l.centerline for l in lanes])
    init_pos = centerline.pointAlongBy(config['ego_init_progress_ratio']*centerline.length)
    blueprint = config['ego_blueprint']
    ego = new Car at init_pos,
      with name 'ego',
      with color Color(0, 1, 0),
      with blueprint blueprint,
      with width blueprint2dims[blueprint]['width'],
      with length blueprint2dims[blueprint]['length'],
      with behavior AutopilotRouteBehavior(turns_from_route(lanes), config_override=VUT_config),
      with physics True,
      with allowCollisions False
