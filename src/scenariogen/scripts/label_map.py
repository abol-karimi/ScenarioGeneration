#!/usr/bin/env python3.8
import argparse
import numpy as np
from scenic.domains.driving.roads import Network
import carla

# This project
from scenariogen.simulators.carla.visualization import draw_lane

parser = argparse.ArgumentParser(description='label the intersections.')
parser.add_argument('-m', '--map_name',
                    help='Carla map name')
parser.add_argument('-i', '--intersections', action='store_true',
                    help='Draw intersections')
parser.add_argument('-l', '--lanes', action='store_true',
                    help='Draw lanes')
args = parser.parse_args()

client = carla.Client('127.0.0.1', 2000)

if args.map_name:
    map_name = args.map_name
    map_path = f'/home/scenariogen/Scenic/assets/maps/CARLA/{map_name}.xodr'
    world = client.load_world(map_name)
    network = Network.fromFile(map_path)
else:
    world = client.get_world()
    carla_map = world.get_map()
    carla_map.save_to_disk('loaded_map.xodr')
    network = Network.fromFile('loaded_map.xodr')

if args.intersections:
    for i in network.intersections:
        centroid = i.polygon.centroid
        print(i.uid, centroid)
        loc = carla.Location(centroid.x, -centroid.y, 0.5)
        world.debug.draw_string(loc, i.uid, life_time=1000)

if args.lanes:
    for lane in network.lanes:
        draw_lane(world, lane)