# Scenic parameters
model scenic.domains.driving.model

scenario EgoScenario(config):
  setup:
    ego_lanes = [network.elements[l] for l in config['ego_route']]
    ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
    ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress_ratio'])
    ego_blueprint = config['ego_blueprint']
    ego = Car at ego_init_pos,
      with name 'ego',
      with blueprint ego_blueprint,
      with width blueprint2dims[ego_blueprint]['width'],
      with length blueprint2dims[ego_blueprint]['length'],
      with behavior FollowLaneBehavior(target_speed=6)
    cars = [ego]