param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.carla.model

monitor Constraint():
  while True:
    require simulation().currentTime < 10
    wait

scenario Main():
  setup:
    ego = new Car on road,
      with behavior FollowLaneBehavior()

    require monitor Constraint()