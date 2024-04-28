#!/usr/bin/env python3

from scenic.domains.driving.roads import Network
from scenariogen.core.utils import geometry_atoms
import argparse
import carla

parser = argparse.ArgumentParser(description='Print the geometric predicates of an intersections.')
parser.add_argument('map_name', help='Carla map name')
parser.add_argument('intersection_uid', help='Carla map name')
args = parser.parse_args()

map_path = f'/home/scenariogen/Scenic/assets/maps/CARLA/{args.map_name}.xodr'
network = Network.fromFile(map_path)
geometry = geometry_atoms(network, args.intersection_uid)

for atom in geometry:
    print(atom)
    