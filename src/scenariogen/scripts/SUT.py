#!/usr/bin/env python3.8
import argparse
import jsonpickle

# This project
from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError


parser = argparse.ArgumentParser(
    description='play the given scenario with a Carla autopilot driving the ego.')
parser.add_argument('seed_path', 
                    help='relative path of the seed')
parser.add_argument('--timestep', type=float, default=0.05,
                    help='length of each simulation step')
parser.add_argument('--no_render', action='store_true',
                    help='disable rendering')
parser.add_argument('--closedLoop', action='store_true',
                    help='simulate a VUT')
parser.add_argument('--ego_module', default='experiments.agents.followLane',
                    help='the scenic file containing the ego scenario')
parser.add_argument('--simulator', choices=['newtonian', 'carla'], default='newtonian',
                    help='The simulator')
parser.add_argument('--raw', action='store_true',
                    help='Replay the original simulation if available, instead of the spline approximation')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int, 
                      help='max number of simulation steps')
duration.add_argument('--seconds', type=float, 
                      help='number of seconds to run the scenario')
args = parser.parse_args()

with open(args.seed_path, 'r') as f:
    seed = jsonpickle.decode(f.read())

# Default duration is the whole scenario:
seconds = seed.timings[0].ctrlpts[-1][0]
# Override with custom duration:
if args.steps:
    seconds = args.steps * args.timestep
elif args.seconds:
    seconds = args.seconds
steps = seconds // args.timestep

# Scenario config
config = {**seed.config}
config['steps'] = steps
config['timestep'] = args.timestep
config['weather'] = 'CloudySunset'
config['seed'] = seed
config['arrival_distance'] = 4
config['stop_speed_threshold'] = 0.5  # meters/seconds
config['closedLoop'] = args.closedLoop
config['ego_module'] = args.ego_module
config['simulator'] = args.simulator
config['render'] = not args.no_render
config['raw'] = args.raw
config['seed_path'] = args.seed_path

try:
    sim_result = Scenario(seed).run(config)
except NonegoNonegoCollisionError as err:
    print(f'Collision between nonegos {err.nonego} and {err.other}.')
except EgoCollisionError as err:
    print(f'Ego collided with {err.other.name}.')
else:
    events = sim_result.records['events']
    for e in events:
        print(e)
