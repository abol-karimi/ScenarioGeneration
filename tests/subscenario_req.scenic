param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/scenariogen/Scenic/assets/maps/CARLA/{carla_map}.xodr'
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