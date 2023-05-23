#!/usr/bin/env python3.8
import argparse
from scenic.domains.driving.roads import Network
import carla
from visualization import draw_intersection, set_camera, draw_lane

parser = argparse.ArgumentParser(
    description='Show a bird-eye view of the intersection.')
parser.add_argument('intersection_uid', help='Scenic uid for the intersection')
parser.add_argument('-m', '--map_name', help='Scenic uid of the Carla map')
drawings = parser.add_mutually_exclusive_group()
parser.add_argument('--all_lanes', action='store_true',
                    help='Draw all lane boundaries')
parser.add_argument('--src',
                    help='Draw the maneuvers starting from the incoming lane')
parser.add_argument('--dest',
                    help='Draw the maneuvers ending in the outgoing lane')
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
intersection = network.elements[args.intersection_uid]

lanes_to_draw = []
if args.src:
    lanes_to_draw.append(network.elements[args.src])
    for m in intersection.maneuvers:
        if m.startLane.uid == args.src:
            lanes_to_draw.append(m.connectingLane)
            lanes_to_draw.append(m.endLane)
elif args.dest:
    lanes_to_draw.append(network.elements[args.dest])
    for m in intersection.maneuvers:
        if m.endLane.uid == args.dest:
            lanes_to_draw.append(m.connectingLane)
            lanes_to_draw.append(m.startLane)
for l in lanes_to_draw:
    draw_lane(world, l, label=True)

draw_intersection(world, intersection, draw_lanes=args.all_lanes)
set_camera(world, intersection, 20)
