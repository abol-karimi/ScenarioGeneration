#!/usr/bin/env python3.8
import argparse
import jsonpickle
import importlib

from scenic.domains.driving.roads import Network

# This project
from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError
from scenariogen.core.coverages.coverage import PredicateCoverage
from experiments.configs import SUT_config, coverage_config


parser = argparse.ArgumentParser(
    description='play the given scenario with a Carla autopilot driving the ego.')
parser.add_argument('seed_path', 
                    help='relative path of the seed')
parser.add_argument('--timestep', type=float,
                    help='length of each simulation step')
parser.add_argument('--weather', type=str,
                    help='weather in the simulation')
parser.add_argument('--render-spectator', action='store_true',
                    help='render a spectator above the intersection')
parser.add_argument('--render-ego', action='store_true',
                    help='render ego viewpoint (only in the Carla simulator)')
parser.add_argument('--ego-module',
                    help='the scenic file containing the ego scenario')
parser.add_argument('--coverage-module',
                    help='the scenic file containing coverage monitor')
parser.add_argument('--simulator', choices=['newtonian', 'carla'], default='carla',
                    help='The simulator')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int, 
                      help='max number of simulation steps')
duration.add_argument('--seconds', type=float, 
                      help='number of seconds to run the scenario')
args = parser.parse_args()

with open(args.seed_path, 'r') as f:
    seed = jsonpickle.decode(f.read())

# Default timestep is defined by the seed
timestep = seed.config['timestep']
if args.timestep:
    timestep = args.timestep

# Default duration is the whole scenario:
seconds = seed.timings[0].knotvector[-1]
if args.steps:
    seconds = args.steps * timestep
elif args.seconds:
    seconds = args.seconds

steps = int(seconds / timestep)

# Default weather is defined by the seed
weather = seed.config['weather']
if args.weather:
    weather = args.weather

# Scenario config
config = {**seed.config, **SUT_config, **coverage_config}
config['simulator'] = args.simulator
config['steps'] = steps
config['timestep'] = timestep
config['weather'] = weather
config['fuzz_input'] = seed
config['ego-module'] = args.ego_module
config['coverage_module'] = args.coverage_module
config['render_spectator'] = args.render_spectator
config['render_ego'] = args.render_ego

sim_result = Scenario(seed).run(config)

if args.coverage_module:
    coverage = sim_result.records['coverage']
    coverage.print()

    config.update({'network': Network.fromFile(config['map'])})
    coverage_module = importlib.import_module(f'scenariogen.core.coverages.{args.coverage_module}')
    predicate_coverage_space = coverage_module.coverage_space(config)
    coverage_gap = predicate_coverage_space - coverage.cast_to(PredicateCoverage)
    print(f'\nPredicate coverage gap:')
    coverage_gap.print()