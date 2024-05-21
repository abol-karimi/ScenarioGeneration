param config = None
config = globalParameters.config

if config['simulator'] != 'carla':
  raise ValueError(f"Behavior is not compatible with the {config['simulator']} simulator!")

# Scenic parameters
model scenic.simulators.carla.model

# imports
from scenariogen.simulators.carla.behaviors import BehaviorAgentFollowRoute


ego_behavior = BehaviorAgentFollowRoute(
                  config['ego_route'],
                  config['ego_init_progress_ratio'],
                  debug=config['render-spectator'])
