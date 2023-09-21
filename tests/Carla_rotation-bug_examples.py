#!/usr/bin/env python3.8
import carla

client = carla.Client('127.0.0.1', 2000)
world = client.load_world('Town05')

blueprint = world.get_blueprint_library().find('vehicle.tesla.model3')

spawn_rot = carla.Rotation(pitch=90, yaw=0, roll=90)
spawn_loc = carla.Location(0, 0, 20)
carlaActor1 = world.try_spawn_actor(blueprint, carla.Transform(spawn_loc, spawn_rot))
carlaActor1.set_simulate_physics(False)

spawn_rot = carla.Rotation(pitch=45, yaw=0, roll=0)
spawn_loc = carla.Location(10, 0, 20)
carlaActor2 = world.try_spawn_actor(blueprint, carla.Transform(spawn_loc, spawn_rot))
carlaActor2.set_simulate_physics(False)

spawn_rot = carla.Rotation(pitch=0, yaw=45, roll=0)
spawn_loc = carla.Location(20, 0, 20)
carlaActor3 = world.try_spawn_actor(blueprint, carla.Transform(spawn_loc, spawn_rot))
carlaActor3.set_simulate_physics(False)

spawn_rot = carla.Rotation(pitch=0, yaw=0, roll=45)
spawn_loc = carla.Location(30, 0, 20)
carlaActor4 = world.try_spawn_actor(blueprint, carla.Transform(spawn_loc, spawn_rot))
carlaActor4.set_simulate_physics(False)

spawn_rot = carla.Rotation(pitch=45, yaw=45, roll=0)
spawn_loc = carla.Location(40, 0, 20)
carlaActor5 = world.try_spawn_actor(blueprint, carla.Transform(spawn_loc, spawn_rot))
carlaActor5.set_simulate_physics(False)

spawn_rot = carla.Rotation(pitch=0, yaw=45, roll=45)
spawn_loc = carla.Location(50, 0, 20)
carlaActor6 = world.try_spawn_actor(blueprint, carla.Transform(spawn_loc, spawn_rot))
carlaActor6.set_simulate_physics(False)

spawn_rot = carla.Rotation(pitch=45, yaw=0, roll=45)
spawn_loc = carla.Location(60, 0, 20)
carlaActor7 = world.try_spawn_actor(blueprint, carla.Transform(spawn_loc, spawn_rot))
carlaActor7.set_simulate_physics(False)

print(carlaActor1.get_transform().rotation)
print(carlaActor2.get_transform().rotation)
print(carlaActor3.get_transform().rotation)
print(carlaActor4.get_transform().rotation)
print(carlaActor5.get_transform().rotation)
print(carlaActor6.get_transform().rotation)
print(carlaActor7.get_transform().rotation)