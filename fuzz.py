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

parser = argparse.ArgumentParser(description='Make new seeds by fuzzing the given seed corpus.')
parser.add_argument('in_corpus', 
                    help='the seed corpus to fuzz')
parser.add_argument('out_corpus', 
                    help='the output corpus file')
parser.add_argument('--iterations', default=1, type=int,
                    help='number of fuzzing iterations')
parser.add_argument('--timestep', default=0.05, type=float, 
                    help='The length of one simulation step')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--maxSteps', type=int, 
                      help='maximum allowed scenario duration in steps. Note that each scenario can have a different duration.')
duration.add_argument('--maxSeconds', type=float, 
                      help='maximum allowed scenario duration in seconds. Note that each scenario can have a different duration.')
parser.add_argument('--ego',
                    help='simulate an ego together with the nonegos')
parser.add_argument('--weather', default = 'CloudySunset')
parser.add_argument('--map_path', default = './maps/Town05.xodr')
parser.add_argument('--map_name', default = 'Town05')
parser.add_argument('--spline_degree', default = 3, type=int)
parser.add_argument('--max_parameters_size', default = 50, type=int)
args = parser.parse_args()

# Default maximum:
maxSteps = 400
# Set maximum duration if requested:
if args.maxSteps:
    maxSteps = args.maxSteps
elif args.maxSeconds:
    maxSteps = args.maxSeconds*args.timestep


# Mutator configs
config = {}
config['maxSteps'] = maxSteps
config['timestep'] = args.timestep
config['weather'] = 'CloudySunset'
config['map_path'] = './maps/Town05.xodr'
config['map_name'] = 'Town05'
config['intersection_uid'] = 'intersection396'
config['rules_path'] = '4way-stopOnAll.lp'
config['arrival_distance'] = 4
config['spline_degree'] = args.spline_degree
config['max_parameters_size'] = args.max_parameters_size
config['max_mutations_per_iteration'] = 4
config['network'] = Network.fromFile(config['map_path'])

# Instantiate a fuzzer
mutator = mutators.RandomMutator(config)
coverage = coverages.PredicateNameCoverage(config=config)
scheduler = schedulers.PriorityScheduler(config=config)
corpus = seed_corpus.SeedCorpus([])
corpus.load(args.in_corpus)
fuzzer = fuzzers.ModularFuzzer(config=config,
                              coverage=coverage,
                              mutator=mutator,
                              scheduler=scheduler,
                              seed_corpus=corpus)

# Run the fuzzer
fuzzer.run(args.iterations, render=False)
corpus.save(args.out_corpus)
