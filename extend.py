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
import seed_corpus
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
config['max_ctrlpts'] = 10
config['max_mutations_per_iteration'] = 4
config['network'] = Network.fromFile(config['map_path'])

# Instantiate a fuzzer
mutator = mutators.RandomMutator(config)
coverage = coverages.PredicateNameCoverage(config=config)
scheduler = schedulers.PriorityScheduler(config=config)
corpus = seed_corpus.SeedCorpus([])
corpus.load('trial1.json')
fuzzer = fuzzers.ModularFuzzer(config=config,
                              coverage=coverage,
                              mutator=mutator,
                              scheduler=scheduler,
                              seed_corpus=corpus)

iterations = 7200

# Run the fuzzer
fuzzer.run(iterations, render=False)
corpus.save('trial2.json')

# Write to file
# with open('seeds.', 'wb') as outFile:
#     pickle.dump(scenario, outFile)