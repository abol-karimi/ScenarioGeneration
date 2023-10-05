#!/usr/bin/env python3.8
import argparse
from scenic.domains.driving.roads import Network
import carla

parser = argparse.ArgumentParser(description='label the intersections.')
parser.add_argument('-m', '--map_name',
                    help='Carla map name')
args = parser.parse_args()

client = carla.Client('127.0.0.1', 2000)

if args.map_name:
    map_name = args.map_name
    map_path = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{map_name}.xodr'
    world = client.load_world(map_name)
    network = Network.fromFile(map_path)
else:
    world = client.get_world()
    carla_map = world.get_map()
    carla_map.save_to_disk('loaded_map.xodr')
    network = Network.fromFile('loaded_map.xodr')

for i in network.intersections:
    signals = [(s.type, s.isTrafficLight) for s in i.signals]
    print(i.uid, signals)
