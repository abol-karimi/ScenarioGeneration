# Scenic parameters
model scenic.domains.driving.model
param config = None
config = globalParameters.config

# imports
import jsonpickle
from scenariogen.core.signals import SignalType
from scenariogen.simulators.newtonian.behaviors import FollowRouteAvoidCollisionsBehavior

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

scenario EgoScenario(config):
  setup:
    ego_lanes = [network.elements[l] for l in config['ego_route']]
    ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
    ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress_ratio'])
    ego_blueprint = config['ego_blueprint']
    ego = new Car at ego_init_pos,
      with name 'ego',
      with blueprint ego_blueprint,
      with width blueprint2dims[ego_blueprint]['width'],
      with length blueprint2dims[ego_blueprint]['length'],
      with signal SignalType.OFF, # TODO SignalType.from_route
      with behavior FollowRouteAvoidCollisionsBehavior(6, ego_lanes)
    cars = [ego]

