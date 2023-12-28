# Scenic parameters
model scenic.simulators.newtonian.driving_model
param config = None
config = globalParameters.config

# imports
import jsonpickle
from scenariogen.simulators.newtonian.behaviors import IntersectionBehavior

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
      with blueprint ego_blueprint,
      with length blueprint2dims[ego_blueprint]['length'],
      with width blueprint2dims[ego_blueprint]['width'],
      with behavior IntersectionBehavior(ego_lanes, target_speed=8, arrival_distance=8)
    cars = [ego]

