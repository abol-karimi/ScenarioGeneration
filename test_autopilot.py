#!/usr/bin/env python3.8
from generator import car_to_time_to_events
from scenic.domains.driving.roads import Network
from solver import ASPSolver
import intersection_monitor
import scenic
import pickle
import argparse

# This project
import seed_corpus


parser = argparse.ArgumentParser(
    description='play the given scenario with a Carla autopilot driving the ego.')
parser.add_argument('corpus', help='filename of the corpus of seeds')
parser.add_argument('seed', type=int, help='seed number to replay')
parser.add_argument('-a', '--aggressiveness', choices=['cautious', 'normal', 'aggressive'],
                    default='normal', help='aggressiveness of Carla BehaviorAgent')
parser.add_argument('--rss', action='store_true', help='enable RSS restrictor')
args = parser.parse_args()

corpus = seed_corpus.SeedCorpus([])
corpus.load(args.corpus)
seed = corpus.seeds[args.seed]

config = {}
config['maxSteps'] = 700
config['timestep'] = 0.05
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
    'autopilot.scenic', params=params)

scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = scenic_scenario.getSimulator()
sim_result = simulator.simulate(
                scene,
                maxSteps=config['maxSteps'],
                maxIterations=1,
                raiseGuardViolations=True
                )