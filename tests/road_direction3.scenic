param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
param weather = 'CloudySunset'
model scenic.simulators.carla.model
param timestep = 0.05
param render = False

import random
from scenariogen.simulators.carla.monitors import ShowIntersectionMonitor

intersection = network.elements['intersection1574']

cars = []
m = Uniform(*intersection.maneuvers)
lanes = (m.startLane, m.connectingLane, m.endLane)
centerline = PolylineRegion.unionAll([l.centerline for l in lanes])
d = centerline.length * random.uniform(0, 1)
p = centerline.pointAlongBy(d)
car = new Car at p,
  with name f'{lanes[0].uid, lanes[1].uid, lanes[2].uid}_{d}',
  with blueprint 'vehicle.tesla.model3',
  with behavior FollowLaneBehavior(target_speed = 1),
  with physics False,
  with allowCollisions True
cars.append(car)

ego = cars[0]

require monitor ShowIntersectionMonitor(intersection, show_carla_axes=True)