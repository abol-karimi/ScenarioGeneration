# Scenic parameters
model scenic.simulators.carla.model

# imports
import numpy as np
from scenariogen.simulators.carla.behaviors import BehaviorAgentFollowWaypoints
from scenariogen.core.geometry import CurvilinearTransform
import jsonpickle

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

scenario EgoScenario(_config):
  setup:
    config = {'aggressiveness': 'normal',
              'use_rss': False,
              **_config}
    lanes = [network.elements[l] for l in config['ego_route']]
    transform = CurvilinearTransform([p for lane in lanes
                                        for p in lane.centerline.lineString.coords
                                        ])
    x0 = transform.axis.length * config['ego_init_progress_ratio']
    y0 = 0
    h0 = 0
    p = transform.rectilinear(x0@y0, h0)
    waypoints_separation = 50
    waypoints = (Vector(*transform.rectilinear(x@0))
                 for x in np.arange(x0+waypoints_separation, transform.axis.length, waypoints_separation))
    ego_blueprint = config['ego_blueprint']
    ego = new Car at p, facing p[2],
      with name 'ego',
      with color Color(0, 1, 0),
      with blueprint config['ego_blueprint'],
      with width blueprint2dims[ego_blueprint]['width'],
      with length blueprint2dims[ego_blueprint]['length'],
      with behavior BehaviorAgentFollowWaypoints(waypoints=waypoints,
                                            aggressiveness=config['aggressiveness'],
                                            use_rss=config['use_rss']),
      with physics True,
      with allowCollisions False