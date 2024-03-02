param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/scenariogen/Scenic/assets/maps/CARLA/{carla_map}.xodr'
model scenic.simulators.carla.model

p0 = network.intersections[0].incomingLanes[0].centerline.pointAlongBy(0)

ego = Car at p0, facing roadDirection,
  with behavior FollowLaneBehavior(4)
