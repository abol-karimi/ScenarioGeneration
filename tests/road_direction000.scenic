param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/scenariogen/Scenic/assets/maps/CARLA/{carla_map}.xodr'
param weather = 'CloudySunset'
model scenic.simulators.carla.model

import numpy as np
from scipy.spatial.transform import Rotation
import carla
from scenic.simulators.carla.utils.utils import scenicToCarlaRotation
from scenariogen.core.geometry import CurvilinearTransform
import scenariogen.simulators.carla.visualization as visualization
from scenariogen.simulators.carla.monitors import ShowIntersectionMonitor

intersection_uid = 'intersection396'
intersection = network.elements[intersection_uid]
lane = intersection.incomingLanes[4]
transform = CurvilinearTransform([p for p in lane.centerline.lineString.coords])
point = new OrientedPoint at lane.centerline[0]

ego = new Car following roadDirection from point for 0
cars = []

ds = np.arange(10, lane.centerline.length, 10)
for d in ds:
  p = transform.rectilinear((d, 0))
  rot = Orientation(Rotation.from_euler("ZXY", [p[2], 0, 0], degrees=False))
  rot_c = scenicToCarlaRotation(rot)
  print(f'Scenic heading {p[2]} is Carla rotation {rot_c.pitch, rot_c.yaw, rot_c.roll}')
  car = new Car at p[0]@p[1], facing p[2],
    with name f'heading: {p[2]}',
    with behavior FollowLaneBehavior(0),
    with rolename 'target' if d == ds[-1] else 'other',
    with physics False,
    with allowCollisions True
  cars.append(car)

require monitor ShowIntersectionMonitor(intersection_uid)