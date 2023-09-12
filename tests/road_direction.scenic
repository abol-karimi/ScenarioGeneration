param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
param weather = 'CloudySunset'
model scenic.simulators.carla.model

intersection = network.elements['intersection396']
lane = intersection.incomingLanes[4]
point = new OrientedPoint at lane.centerline[0]

ego = new Car following roadDirection from point for 0

for d in (10, 20, 30, 40):
  car = new Car following roadDirection from point for d