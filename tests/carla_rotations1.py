#!/usr/bin/env python3
from scipy.spatial.transform import Rotation
import carla

client = carla.Client('127.0.0.1', 2000)
world = client.load_world('Town05')

def diff(rot1, rot2):
  x_axis = (1, 0, 0)
  v1 = rot1.apply(x_axis)
  v2 = rot2.apply(x_axis)
  rot, rssd = Rotation.align_vectors((v1,), (v2,))
  return rot, rssd

def scipy_to_carla(rot):
  return carla.Rotation(*rot.as_euler('yzx', degrees=True))

def carla_to_scipy(rot):
  return Rotation.from_euler('yzx', (rot.pitch, rot.yaw, rot.roll), degrees=True)

if __name__ == '__main__':
  blueprint = world.get_blueprint_library().find('vehicle.tesla.model3')
  loc_spawn = carla.Location(0, 0, 3)
  
  for i in range(10000):
    rot_spawn = Rotation.random()

    rot_spawn_carla = scipy_to_carla(rot_spawn)
    actor = world.try_spawn_actor(blueprint, carla.Transform(loc_spawn, rot_spawn_carla))
    actor.set_simulate_physics(False)

    rot_query_carla = actor.get_transform().rotation
    rot_query = carla_to_scipy(rot_query_carla)

    rot, rssd = diff(rot_spawn, rot_query)
    if rssd > 0.1:
      print(f'Spawned with {rot_spawn_carla}')
      print(f'Measured as {rot_query_carla}')
      print(f'Rotation difference: {scipy_to_carla(rot)}, with RSSD: {rssd}')
    
    actor.destroy()

