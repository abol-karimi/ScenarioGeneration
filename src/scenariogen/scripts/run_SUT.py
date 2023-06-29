#!/usr/bin/env python3.8
import argparse
import random
import jsonpickle

# This project
from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, InvalidSeedError


parser = argparse.ArgumentParser(
    description='play the given scenario with a Carla autopilot driving the ego.')
parser.add_argument('seed', 
                    help='relative path of seed')
parser.add_argument('--timestep', type=float, default=0.05,
                    help='length of each simulation step')
parser.add_argument('--no_render', action='store_true',
                    help='disable rendering')
parser.add_argument('--closedLoop', action='store_true',
                    help='simulate a VUT')
parser.add_argument('--ego_module', default='scenariogen.simulators.newtonian.ego_followLane',
                    help='the scenic file containing the ego scenario')
parser.add_argument('--simulator', choices=['newtonian', 'carla'], default='newtonian',
                    help='The simulator')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int, 
                      help='max number of simulation steps')
duration.add_argument('--seconds', type=float, 
                      help='max seconds to replay')
args = parser.parse_args()

with open(args.seed, 'r') as f:
    seed = jsonpickle.decode(f.read())

# Default duration is the whole scenario:
seconds = seed.trajectories[0].ctrlpts[-1][2]
# Override with custom duration:
if args.steps:
    seconds = args.steps * args.timestep
elif args.seconds:
    seconds = args.seconds
steps = seconds // args.timestep

# Choose a blueprint of an appropriate size for each non-ego
with open('src/scenariogen/simulators/carla/blueprint_library.json', 'r') as f:
    blueprints = jsonpickle.decode(f.read())
dim2bp = {}
for b, dims in blueprints.items():
    length = int(100*dims['length'])
    width = int(100*dims['width'])
    if not (length, width) in dim2bp:
        dim2bp[(length, width)] = [b]
    else:
        dim2bp[(length, width)].append(b)
bps = [random.choice(dim2bp[(int(l*100), int(w*100))])
       for l, w in zip(seed.lengths, seed.widths)]

# Scenario config
config = {**seed.config}
config['steps'] = steps
config['timestep'] = args.timestep
config['weather'] = 'CloudySunset'
config['seed'] = seed
config['arrival_distance'] = 4
config['stop_speed_threshold'] = 0.5  # meters/seconds
config['blueprints'] = bps
config['closedLoop'] = args.closedLoop
config['ego_module'] = args.ego_module
config['simulator'] = args.simulator

try:
    sim_result = Scenario(seed).run(config)
except InvalidSeedError:
    print('Invalid seed.')
except EgoCollisionError:
    print('SUT failure: VUT collision.')

events = sim_result.records['events']
for e in events:
    print(e)
