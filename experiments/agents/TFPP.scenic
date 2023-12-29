# Scenic parameters
model scenic.simulators.carla.model

# imports
import jsonpickle
from scenariogen.simulators.carla.behaviors import LeaderboardAgentBehavior


with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

scenario EgoScenario(config):
  setup:
    if config['simulator'] != 'carla':
      raise ValueError(f"BehaviorAgent is not compatible with the {config['simulator']} simulator!")
    
    ego_lanes = [network.elements[l] for l in config['ego_route']]
    ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
    ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress_ratio']*ego_centerline.length)
    ego_blueprint = config['ego_blueprint']

    agent = '/home/carla/carla_garage_fork/team_code/sensor_agent'
    agent_config = '/home/carla/carla_garage_fork/pretrained_models/leaderboard/tfpp_wp_all_0'
    track = 'SENSORS'
    keypoints = (ego_init_pos, ego_centerline[-1])
    
    ego = new Car at ego_init_pos,
      with name 'ego',
      with rolename 'hero',
      with color Color(0, 1, 0),
      with blueprint config['ego_blueprint'],
      with width blueprint2dims[ego_blueprint]['width'],
      with length blueprint2dims[ego_blueprint]['length'],
      with behavior LeaderboardAgentBehavior(agent, agent_config, track, keypoints, debug=True),
      with physics True,
      with allowCollisions False
