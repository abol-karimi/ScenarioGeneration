param config = None
config = globalParameters.config

if config['simulator'] != 'carla':
  raise ValueError(f"autopilot is not compatible with the {config['simulator']} simulator!")

# Scenic parameters
model scenic.simulators.carla.model

# imports
from scenariogen.simulators.carla.behaviors import AutopilotRouteBehavior
from scenariogen.core.utils import turns_from_route
from evaluation.agents.configs import autopilot_config

lanes = [network.elements[l] for l in config['ego_route']]

ego_behavior = AutopilotRouteBehavior(turns_from_route(lanes), config_override=autopilot_config)
