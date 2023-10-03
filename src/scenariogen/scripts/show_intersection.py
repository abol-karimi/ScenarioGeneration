#!/usr/bin/env python3.8
import argparse
from scenic.domains.driving.roads import Network
import carla
from scenariogen.simulators.carla.visualization import draw_arrival, set_camera, draw_lane

parser = argparse.ArgumentParser(
    description='Show a bird-eye view of the intersection.')
parser.add_argument('intersection_uid', help='Scenic uid for the intersection')
parser.add_argument('-m', '--map_name', help='Name of the Carla map')
parser.add_argument('--no_boundaries', action='store_true',
                    help='Draw lane boundaries')
parser.add_argument('--no_labels', action='store_true',
                    help='Draw lane boundaries')
parser.add_argument('--arrival', action='store_true',
                    help='Draw the arrival box for arrival to the intersection')
parser.add_argument('--arrival_dist', type=float, default=4,
                    help='Arrival distance to the intersection')
drawings = parser.add_mutually_exclusive_group()
drawings.add_argument('--outside', action='store_true',
                    help='Draw the incoming and outgoing lanes')
drawings.add_argument('--inside', action='store_true',
                    help='Draw the connecting lanes')
drawings.add_argument('--all', action='store_true',
                    help='Draw both the incoming and outgoing lanes')
drawings.add_argument('--src', action='store_true',
                    help='Draw the maneuvers starting from the incoming lane')
drawings.add_argument('--dest', action='store_true',
                    help='Draw the maneuvers ending in the outgoing lane')
parser.add_argument('--height', default=30, type=float)
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

# Disable synchronous mode
settings = world.get_settings()
settings.synchronous_mode = False
world.apply_settings(settings)

intersection = network.elements[args.intersection_uid]

if args.arrival:
    draw_arrival(world, intersection, args.arrival_dist)

lanes_to_draw = []
boundaries = not args.no_boundaries
label = not args.no_labels
if args.outside:
    for lane in intersection.incomingLanes + intersection.outgoingLanes:
        draw_lane(world, lane, boundaries=boundaries, label=label)
elif args.inside:
    for m in intersection.maneuvers:
        draw_lane(world, m.connectingLane, boundaries=boundaries, label=args.no_labels)
elif args.all:
    for lane in intersection.incomingLanes + intersection.outgoingLanes:
        draw_lane(world, lane, boundaries=boundaries, label=label)
    for m in intersection.maneuvers:
        draw_lane(world, m.connectingLane, boundaries=boundaries, label=label)
elif args.src:
    draw_lane(world, network.elements[args.src])
    for m in intersection.maneuvers:
        if m.startLane.uid == args.src:
            draw_lane(world, m.connectingLane)
            draw_lane(world, m.endLane)
elif args.dest:
    draw_lane(world, network.elements[args.dest])
    for m in intersection.maneuvers:
        if m.endLane.uid == args.dest:
            draw_lane(world, m.connectingLane)
            draw_lane(world, m.startLane)

set_camera(world, intersection, args.height)

# Enable synchronous mode
settings = world.get_settings()
settings.synchronous_mode = True
world.apply_settings(settings)