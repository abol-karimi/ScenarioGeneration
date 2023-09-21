#!/usr/bin/env python3.8
import carla

client = carla.Client('127.0.0.1', 2000)
world = client.load_world('Town05')

def draw_transform(world, translation=carla.Location(), rotation=carla.Rotation()):
    world.debug.draw_arrow(translation, translation + rotation.get_forward_vector(), color=carla.Color(255, 0, 0))
    world.debug.draw_arrow(translation, translation + rotation.get_right_vector(), color=carla.Color(0, 255, 0))
    world.debug.draw_arrow(translation, translation + rotation.get_up_vector(), color=carla.Color(0, 0, 255))

blueprint = world.get_blueprint_library().find('vehicle.audi.a2')
actors = []
for pitch in range(-80, 80, 20):
   for yaw in range(-180, 180, 20):
      rot = carla.Rotation(pitch=pitch, yaw=yaw)
      axes_loc = carla.Location(0, 0, 50) + rot.get_forward_vector()*35
      spawn_loc = carla.Location(0, 0, 50) + rot.get_forward_vector()*30
      draw_transform(world, axes_loc, rot)
      try:
        actor = world.spawn_actor(blueprint, carla.Transform(spawn_loc, rot))
      except Exception as e:
         print(e)       
         print(rot)
         continue
      actor.set_simulate_physics(False)
      actors.append(actor)
