#!/usr/bin/env python3.8

# Standard libraries
import importlib
import argparse
import pickle
import jsonpickle
import numpy as np

# Scenic modules
import scenic
from scenic.domains.driving.roads import Network
from scenic.simulators.newtonian import NewtonianSimulator

# My modules
import seed_corpus
from utils import spacetime_trajectories, spline_approximation

#----------Main Script----------
parser = argparse.ArgumentParser(description='Make a seed from a scenic scenario.')
parser.add_argument('scenic_file', help='Scenic file specifying the scenario')
parser.add_argument('corpus_file', help='Seed corpus to save the generated seed in')
parser.add_argument('--maxSteps', default=700, type=int)
parser.add_argument('--weather', default = 'CloudySunset')
parser.add_argument('--map_path', default = './maps/Town05.xodr')
parser.add_argument('--map_name', default = 'Town05')
parser.add_argument('--spline_degree', default = 3, type=int)
parser.add_argument('--ctrlpts_size', default = 10, type=int)
args = parser.parse_args()

# Run the scenario
scenic_scenario = scenic.scenarioFromFile(
    args.scenic_file,
    model='scenic.simulators.newtonian.driving_model')
scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = NewtonianSimulator()
sim_result = simulator.simulate(
                scene,
                maxSteps=args.maxSteps,
                maxIterations=1,
                raiseGuardViolations=True
                )

# Convert the result to a seed
routes = sim_result.records['routes']
signals = sim_result.records['turn_signals']
timestep = scene.params['timestep']
spacetime_trajs = spacetime_trajectories(sim_result, timestep)
curves = [spline_approximation(traj, args.spline_degree, args.ctrlpts_size) 
          for traj in spacetime_trajs]
seed = seed_corpus.Seed(routes=routes, curves=curves, signals=signals)
corpus = seed_corpus.SeedCorpus([seed])
corpus.save(args.corpus_file)
