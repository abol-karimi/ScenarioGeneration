#!/usr/bin/env python3.8

# Standard libraries
import importlib
import argparse
import pickle
import jsonpickle
import numpy as np
from geomdl import BSpline

# Scenic modules
from scenic.domains.driving.roads import Network

# My modules
import seed
import mutators
import fuzzers
import schedulers
import coverages
from signals import SignalType
from utils import route_length

# Mutator configs
config = {}
config['maxSteps'] = 700
config['timestep'] = 0.05
config['weather'] = 'CloudySunset'
config['map_path'] = './maps/Town05.xodr'
config['map_name'] = 'Town05'
config['intersection_uid'] = 'intersection396'
config['rules_path'] = '4way-stopOnAll.lp'
config['arrival_distance'] = 4
config['interpolation_degree'] = 2
config['interpolation_max_ctrlpts'] = 10
config['network'] = Network.fromFile(config['map_path'])

# Instantiate a fuzzer
mutator = mutators.RandomMutator(config)
coverage = coverages.PredicateNameCoverage(config=config)
scheduler = schedulers.PriorityScheduler(config=config)
fuzzer = fuzzers.ModularFuzzer(config=config,
                              coverage=coverage,
                              mutator=mutator,
                              scheduler=scheduler)
# Initial seeds for the fuzzing
network = config['network']
intersection = network.elements[config['intersection_uid']]
routes = [(m.startLane, m.connectingLane, m.endLane)
          for m in intersection.maneuvers]
config['ego_route']= [l.uid for l in routes[0]]
config['ego_distance'] = 10

T = config['maxSteps']*config['timestep']

route0 = routes[1]
D = route_length(route0)
degree = config['interpolation_degree']
ts = [T*i/degree for i in range(degree+1)]
ds = [D*i/degree for i in range(degree+1)]
curve0 = BSpline.Curve(normalize_kv = False)
curve0.degree = degree
curve0.ctrlpts = [[t, d] for t,d in zip(ts,ds)]
curve0.knotvector = [ts[0] for i in range(degree)] \
              + list(np.linspace(ts[0], ts[-1], num=len(ts)-degree+1)) \
              + [ts[-1] for i in range(degree)]
seed0 = seed.Seed(routes=[seed.Route(lanes=[l.uid for l in route0])], 
                  curves=[curve0], 
                  signals=[SignalType.LEFT])
initial_seeds = [seed0]
iterations = 4

# Run the fuzzer
seeds = fuzzer.run(initial_seeds, iterations, render=False)

# Write to file
# with open('seeds.', 'wb') as outFile:
#     pickle.dump(scenario, outFile)