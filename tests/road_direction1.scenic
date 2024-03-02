param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/scenariogen/Scenic/assets/maps/CARLA/{carla_map}.xodr'
param weather = 'CloudySunset'
model scenic.simulators.carla.model
param timestep = 0.05
param render = False

import random
from scenariogen.simulators.carla.monitors import ShowIntersectionMonitor

intersection = network.elements['intersection396']

cars = []
for lane in intersection.incomingLanes:
  d = lane.centerline.length * random.uniform(0.01, 0.99)
  p = lane.centerline.pointAlongBy(d)
  car = new Car at p, facing roadDirection,
    with name f'{lane.uid}_{d}',
    with blueprint 'vehicle.tesla.model3',
    with behavior FollowLaneBehavior(target_speed = 1),
    with physics False,
    with allowCollisions True
  cars.append(car)

ego = cars[0]

require monitor ShowIntersectionMonitor(intersection)