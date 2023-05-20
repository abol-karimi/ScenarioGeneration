#!/usr/bin/env python3.8
from scenic.domains.driving.roads import Network
import argparse
import scenic

# This project
import seed_corpus

parser = argparse.ArgumentParser(description='play the given scenario.')
parser.add_argument('corpus', help='filename of the corpus of seeds')
parser.add_argument('seed', type=int, help='seed number to replay')
parser.add_argument('--timestep', type=float, 
                    default=0.05, 
                    help='length of each simulation step, controls replay speed.')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int, help='max number of steps to replay')
duration.add_argument('--seconds', type=float, help='max seconds to replay')
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

# Run the scenario on the seed
params = {'config': config,
        'render': True,
        'seed': seed}

scenic_scenario = scenic.scenarioFromFile(
    'replay.scenic', params=params)

scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = scenic_scenario.getSimulator()
sim_result = simulator.simulate(
                scene,
                maxSteps=config['steps'],
                maxIterations=1,
                raiseGuardViolations=True
                )