config = globalParameters.config

if config['simulator'] != 'carla':
  raise ValueError(f"TF++ is not compatible with the {config['simulator']} simulator!")

# Scenic parameters
model scenic.simulators.carla.model

# imports
from scenariogen.simulators.carla.behaviors import LeaderboardAgentBehavior
    
ego_lanes = [network.elements[l] for l in config['ego_route']]
ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress_ratio']*ego_centerline.length)

agent = '/home/ak/carla_garage_fork/team_code/sensor_agent'
agent_config = '/home/ak/carla_garage_fork/pretrained_models/leaderboard/tfpp_wp_all_0'
track = 'SENSORS'
keypoints = (ego_init_pos, ego_centerline[-1])

ego_behavior = LeaderboardAgentBehavior(agent, agent_config, track, keypoints, debug=config['render-spectator'])