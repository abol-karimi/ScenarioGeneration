#!/usr/bin/env python3.8

from scenic.domains.driving.roads import Network
from src.scenariogen.core.utils import geometry_atoms
import argparse
import carla

parser = argparse.ArgumentParser(description='Print the geometric predicates of an intersections.')
parser.add_argument('intersection_uid', help='Carla map name')
parser.add_argument('--map_name', help='Carla map name')
args = parser.parse_args()

client = carla.Client('127.0.0.1', 2000)

if args.map_name:
    map_name = args.map_name
    map_path = f'./maps/{map_name}.xodr'
    world = client.load_world(map_name)
    network = Network.fromFile(map_path)
else:
    world = client.get_world()
    carla_map = world.get_map()
    carla_map.save_to_disk('loaded_map.xodr')
    network = Network.fromFile('loaded_map.xodr')

geometry = geometry_atoms(network, args.intersection_uid)

for atom in geometry:
    print(atom)
    