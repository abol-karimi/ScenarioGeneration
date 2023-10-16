# Scenic parameters
model scenic.simulators.carla.model

# imports
import jsonpickle
from scenariogen.core.signals import SignalType
from scenariogen.simulators.carla.behaviors import BehaviorAgentReachDestination


with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

scenario EgoScenario(config):
  setup:
    ego_lanes = [network.elements[l] for l in config['ego_route']]
    ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
    ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress_ratio']*ego_centerline.length)
    ego_blueprint = config['ego_blueprint']
    ego = new Car at ego_init_pos,
      with name 'ego',
      with color Color(0, 1, 0),
      with blueprint config['ego_blueprint'],
      with width blueprint2dims[ego_blueprint]['width'],
      with length blueprint2dims[ego_blueprint]['length'],
      with behavior BehaviorAgentReachDestination(route=config['ego_route']),
      with physics True,
      with allowCollisions False
