#!/usr/bin/env python3.8
from itertools import product
import carla

client = carla.Client('127.0.0.1', 2000)
world = client.load_world('Town05')

blueprint = world.get_blueprint_library().find('vehicle.tesla.model3')
loc_spawn = carla.Location(0, 0, 3)
pitch_range = set()
yaw_range = set()
roll_range = set()

bounds = range(-180, 180, 30)
for pitch, yaw, roll in product(bounds, bounds, bounds):
  rot_spawn = carla.Rotation(pitch=pitch, yaw=yaw, roll=roll)
  actor = world.try_spawn_actor(blueprint, carla.Transform(loc_spawn, rot_spawn))
  actor.set_simulate_physics(False)

  rot_query = actor.get_transform().rotation
  pitch_range.add(rot_query.pitch)
  yaw_range.add(rot_query.yaw)
  roll_range.add(rot_query.roll)
  
  actor.destroy()

print(f'pitch range: {min(pitch_range), max(pitch_range)}')
print(f'yaw range: {min(yaw_range), max(yaw_range)}')
print(f'roll range: {min(roll_range), max(roll_range)}')
