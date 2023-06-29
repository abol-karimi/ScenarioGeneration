# Scenic parameters
model scenic.domains.driving.model
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
      with width 2.163450002670288,
      with length 4.791779518127441,
      with blueprint 'vehicle.tesla.model3',
      with signal SignalType.OFF,
      with behavior FollowLaneBehavior(target_speed=6)
    cars = [ego]