param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.carla.model

scenario Actors():
  setup:
    ego = new Car on road,
      with behavior FollowLaneBehavior()

actors_scenario = Actors()

scenario Main():
  compose:
    do actors_scenario