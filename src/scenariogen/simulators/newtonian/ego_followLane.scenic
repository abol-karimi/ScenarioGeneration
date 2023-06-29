# Scenic parameters
model scenic.simulators.newtonian.driving_model
param config = None
config = globalParameters.config

# imports
from scenariogen.core.signals import SignalType

scenario EgoScenario():
  setup:
    ego_lanes = [network.elements[l] for l in config['ego_route']]
    ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
    ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress'])
    ego = Car at ego_init_pos,
      with name 'ego',
      with blueprint 'vehicle.ford.crown',
      with signal SignalType.OFF,
      with behavior FollowLaneBehavior()
    cars = [ego]