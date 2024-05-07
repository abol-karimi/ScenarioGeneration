param config = None
config = globalParameters.config

if config['simulator'] != 'carla':
  raise ValueError(f"Behavior is not compatible with the {config['simulator']} simulator!")

# Scenic parameters
model scenic.simulators.carla.model

# imports
from scenariogen.simulators.carla.behaviors import BehaviorAgentRSSReachDestination
   
ego_lanes = [network.elements[l] for l in config['ego_route']]
ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])

ego_behavior = BehaviorAgentRSSReachDestination(ego_centerline[-1], debug=True)
