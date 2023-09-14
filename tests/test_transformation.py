#!/usr/bin/env python3.8

from scipy.spatial.transform import Rotation
import carla
import scenic
from scenic.core.vectors import Orientation, Vector

from scenic.simulators.carla.utils.utils import scenicToCarlaLocation, scenicToCarlaRotation
yaw_scenic = 0
pitch_scenic = 0
roll_scenic = 0
rot_scenic = Orientation(Rotation.from_euler("ZXY",
                                             [yaw_scenic, pitch_scenic, roll_scenic],
                                             degrees=False))
loc_scenic = Vector(0, 0, 0)


loc_carla = scenicToCarlaLocation(loc_scenic, z=loc_scenic.z)
rot_carla = scenicToCarlaRotation(rot_scenic)
transform = carla.Transform(loc_carla, rot_carla)

print(f"Location {loc_scenic} in scenic's frame is {loc_carla} in Carla's frame.")
print(f"Rotation (yaw={rot_scenic.yaw}, pitch={rot_scenic.pitch}, roll={rot_scenic.roll}) in scenic's frame is {rot_carla} in Carla's frame.")