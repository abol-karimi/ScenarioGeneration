#!/usr/bin/env python3.8

# Standard libraries
import argparse
import pickle

# Scenic modules
import scenic
from scenic.domains.driving.roads import Network
from scenic.simulators.newtonian import NewtonianSimulator

# My modules
import seed_corpus
from utils import spacetime_trajectories, spline_approximation

#----------Main Script----------
parser = argparse.ArgumentParser(description='Make a seed from a scenic scenario.')
parser.add_argument('scenic_file', 
                    help='Scenic file specifying the scenario')
parser.add_argument('corpus_file', 
                    help='Seed corpus to save the generated seed in')
parser.add_argument('--append', action='store_true', 
                    help='add the new seed to the corpus')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int,
                      help='The duration of the scenario in steps')
duration.add_argument('--seconds', type=float, 
                      help='The duration of the scenario in seconds')
parser.add_argument('--timestep', default=0.05, type=float, 
                    help='The length of one simulation step')
parser.add_argument('--weather', default = 'CloudySunset')
parser.add_argument('--map_path', default = './maps/Town05.xodr')
parser.add_argument('--map_name', default = 'Town05')
parser.add_argument('--spline_degree', default = 3, type=int)
parser.add_argument('--parameters_size', default = 50, type=int)
args = parser.parse_args()

# Default duration:
seconds = 20
# Override with custom duration:
if args.steps:
    seconds = args.steps * args.timestep
elif args.seconds:
    seconds = args.seconds
steps = seconds // args.timestep

# Run the scenario
scenic_scenario = scenic.scenarioFromFile(
    args.scenic_file,
    model='scenic.simulators.newtonian.driving_model')
scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = NewtonianSimulator()
sim_result = simulator.simulate(
                scene,
                maxSteps=steps,
                maxIterations=1,
                raiseGuardViolations=True
                )

# Convert the result to a seed
routes = sim_result.records['routes']
signals = sim_result.records['turn_signals']
lengths = sim_result.records['lengths']
widths = sim_result.records['widths']
spacetime_trajs = spacetime_trajectories(sim_result, args.timestep)

#for debugging
with open('spacetime_trajectories.pickle', 'wb') as outFile:
    pickle.dump(spacetime_trajs, outFile)

trajectories = [spline_approximation(traj,
                                     degree=args.spline_degree,
                                     knots_size=args.parameters_size)
          for traj in spacetime_trajs]
seed = seed_corpus.Seed(routes=routes, 
                        trajectories=trajectories, 
                        signals=signals,
                        lengths=lengths, 
                        widths=widths)
# Store the corpus
corpus = seed_corpus.SeedCorpus()
if args.append:
    corpus.load(args.corpus_file)
corpus.add(seed)
corpus.save(args.corpus_file)
