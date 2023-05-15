#!/usr/bin/env python3.8

# Standard libraries
import importlib
import argparse
import pickle
import jsonpickle
import numpy as np
from geomdl import BSpline, fitting
import geomdl

# Scenic modules
import scenic
from scenic.domains.driving.roads import Network
from scenic.simulators.newtonian import NewtonianSimulator

# My modules
import seed_corpus
from utils import car_to_distances

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
init_distances = sim_result.records['init_distances']
car2distances = car_to_distances(sim_result, init_distances)
timestep = scene.params['timestep']
ts = np.arange(0, timestep*(args.maxSteps+1), timestep).tolist()
curves = []
degree = args.spline_degree
knotvector = [ts[0] for i in range(degree)] \
              + list(np.linspace(ts[0], ts[-1], num=len(ts)-degree+1)) \
              + [ts[-1] for i in range(degree)]
for ds in car2distances:
  points = [(t,d) for t,d in zip(ts, ds)]
  approx = fitting.approximate_curve(points, 
                                    degree, 
                                    ctrlpts_size=args.ctrlpts_size)
  curve = geomdl.BSpline.Curve(normalize_kv=False)
  curve.degree = approx.degree
  curve.ctrlpts = approx.ctrlpts
  T = timestep*args.maxSteps
  curve.knotvector = [k*T for k in approx.knotvector]
  curves.append(curve)
  
seed = seed_corpus.Seed(routes=routes, curves=curves, signals=signals)
corpus = seed_corpus.SeedCorpus([seed])
corpus.save(args.corpus_file)
