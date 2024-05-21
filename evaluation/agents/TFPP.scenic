config = globalParameters.config

if config['simulator'] != 'carla':
  raise ValueError(f"TF++ is not compatible with the {config['simulator']} simulator!")

# Scenic parameters
model scenic.simulators.carla.model

# imports
from scenariogen.simulators.carla.behaviors import LeaderboardAgentFollowRouteBehavior


agent = '/home/scenariogen/carla_garage_fork/team_code/sensor_agent'
agent_config = '/home/scenariogen/carla_garage_fork/pretrained_models/leaderboard/tfpp_wp_all_0'
track = 'SENSORS'

ego_behavior = LeaderboardAgentFollowRouteBehavior(
                    agent,
                    agent_config,
                    track,
                    config['ego_route'],
                    config['ego_init_progress_ratio'],
                    debug=config['render-spectator'])