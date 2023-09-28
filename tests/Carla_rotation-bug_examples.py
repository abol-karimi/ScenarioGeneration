#!/usr/bin/env python3.8
import carla

def draw_transform(world, translation=carla.Location(), rotation=carla.Rotation()):
    world.debug.draw_arrow(translation, translation + rotation.get_forward_vector(), color=carla.Color(255, 0, 0))
    world.debug.draw_arrow(translation, translation + rotation.get_right_vector(), color=carla.Color(0, 255, 0))
    world.debug.draw_arrow(translation, translation + rotation.get_up_vector(), color=carla.Color(0, 0, 255))

client = carla.Client('127.0.0.1', 2000)
world = client.load_world('Town05')

draw_transform(world, translation=carla.Location(0, 0, 3))

blueprint = world.get_blueprint_library().find('vehicle.tesla.model3')
spawn_rot = carla.Rotation(pitch=-180, yaw=45, roll=180)
spawn_loc = carla.Location(0, 0, 1)
carlaActor1 = world.try_spawn_actor(blueprint, carla.Transform(spawn_loc, spawn_rot))
carlaActor1.set_simulate_physics(False)

print(carlaActor1.get_transform().rotation)