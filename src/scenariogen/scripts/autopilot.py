#!/usr/bin/env python3.8
import random
import jsonpickle
import scenic
import argparse

# This project
import scenariogen.core.seed as seed

parser = argparse.ArgumentParser(
    description='play the given scenario with a Carla autopilot driving the ego.')
parser.add_argument('corpus', 
                    help='filename of the corpus of seeds')
parser.add_argument('seed', type=int, 
                    help='seed number to replay')
parser.add_argument('--timestep', type=float, default=0.05,
                    help='length of each simulation step')
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
                    help='ego route (list of lane id\'s)')
parser.add_argument('--ego_init_progress', type=float,
                    help='ego\'s initial progress along its route')
parser.add_argument('--rss', action='store_true', help='enable RSS restrictor')
args = parser.parse_args()

corpus = seed.SeedCorpus([])
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

# Choose a blueprint of an appropriate size for each non-ego
with open('carla_blueprint_library.json', 'r') as f:
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

config = {}
config['steps'] = steps
config['timestep'] = args.timestep
config['weather'] = 'CloudySunset'
config['intersection'] = corpus.config['intersection']
config['arrival_distance'] = 4
config['stop_speed_threshold'] = 0.5  # meters/seconds
config['aggressiveness'] =  args.aggressiveness
config['rss_enabled'] = args.rss
config['ego_route'] = args.ego_route if args.ego_route else corpus.config['ego_route']
config['ego_init_progress'] = args.ego_init_progress if args.ego_init_progress else corpus.config['ego_init_progress']
config['blueprints'] = bps

# Run the scenario on the seed
params = {'carla_map': corpus.config['carla_map'],
          'map': corpus.config['map'],
          'config': config,
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
