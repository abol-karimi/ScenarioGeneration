#!/usr/bin/env python3.8

from scenic.domains.driving.roads import Network
from utils import geometry_atoms
import argparse

parser = argparse.ArgumentParser(description='label the intersections.')
parser.add_argument('map_name', help='Carla map name')
parser.add_argument('intersection_uid', help='Carla map name')
args = parser.parse_args()

map_name = args.map_name
map_path = f'./maps/{map_name}.xodr'

network = Network.fromFile(map_path)
geometry = geometry_atoms(network, args.intersection_uid)

for atom in geometry:
    print(atom)
    