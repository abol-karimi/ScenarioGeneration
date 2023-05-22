#!/usr/bin/env python3.8
from scenic.domains.driving.roads import Network
import scenic
import argparse

# This project
import seed_corpus

parser = argparse.ArgumentParser(
    description='play the given scenario with a Carla autopilot driving the ego.')
parser.add_argument('corpus', 
                    help='filename of the corpus of seeds')
parser.add_argument('seed', type=int, 
                    help='seed number to replay')
parser.add_argument('--timestep', type=float, 
                    default=0.05, 
                    help='length of each simulation step, controls simulation speed.')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int, 
                      help='max number of simulation steps')
duration.add_argument('--seconds', type=float, 
                      help='max seconds to replay')
parser.add_argument('-a', '--aggressiveness', 
                    choices=['cautious', 'normal', 'aggressive'],
                    default='normal', 
                    help='aggressiveness of Carla BehaviorAgent')
parser.add_argument('-r', '--ego_route',
                    default=('road9_lane2', 'road45_lane1'), 
                    help='ego route (incoming lane, outgoing lane)')
parser.add_argument('--rss', action='store_true', help='enable RSS restrictor')
args = parser.parse_args()

corpus = seed_corpus.SeedCorpus([])
corpus.load(args.corpus)
seed = corpus.seeds[args.seed]

# Default duration is the whole scenario:
seconds = seed.trajectories[0].ctrlpts[-1][2]
# Override with custom duration:
if args.steps:
    seconds = args.steps * args.timestep
elif args.seconds:
    seconds = args.seconds
steps = seconds // args.timestep

config = {}
config['steps'] = steps
config['timestep'] = args.timestep
config['weather'] = 'CloudySunset'
config['map_path'] = './maps/Town05.xodr'
config['map_name'] = 'Town05'
config['intersection_uid'] = 'intersection396'
config['arrival_distance'] = 4
config['network'] = Network.fromFile(config['map_path'])
config['stop_speed_threshold'] = 0.5  # meters/seconds
config['aggressiveness'] =  args.aggressiveness
config['rss_enabled'] = args.rss
config['ego_route'] = args.ego_route

# Run the scenario on the seed
params = {'config': config,
          'timestep': args.timestep,
          'render': True,
          'seed': seed}

print('Play an autopilot ego in the scenario...')
scenic_scenario = scenic.scenarioFromFile(
    'autopilot.scenic', params=params)

scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = scenic_scenario.getSimulator()
sim_result = simulator.simulate(
                scene,
                maxSteps=config['steps'],
                maxIterations=1,
                raiseGuardViolations=True
                )
