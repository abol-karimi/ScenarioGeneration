param config = None
config = globalParameters.config

if config['simulator'] != 'newtonian':
  raise ValueError(f"IntersectionAgent is not compatible with the {config['simulator']} simulator!")

# Scenic parameters
model scenic.simulators.newtonian.driving_model

# imports
from scenariogen.simulators.newtonian.behaviors import IntersectionBehavior

ego_lanes = [network.elements[l] for l in config['ego_route']]
ego_behavior = IntersectionBehavior(ego_lanes, target_speed=3, turn_speed=2, arrival_distance=config['arrival_distance'])
