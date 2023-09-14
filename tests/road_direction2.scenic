param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
param weather = 'CloudySunset'
model scenic.simulators.carla.model
param timestep = 0.01

import random
from scenariogen.simulators.carla.monitors import ShowIntersectionMonitor

intersection = network.elements['intersection396']

cars = []
for lane in intersection.incomingLanes:
  d = lane.centerline.length * random.uniform(0, 1)
  p = lane.centerline.pointAlongBy(d)
  car = new Car at p,
    with name f'{lane.uid}_{d}',
    with behavior FollowLaneBehavior(target_speed = 1)
  cars.append(car)

ego = cars[0]

require monitor ShowIntersectionMonitor(intersection)