#!/usr/bin/env python3.8

# Standard libraries
import argparse
import copy

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
parser.add_argument('--max_nonegos', type=int, default=5,
                      help='maximum number of non-egos allowed')
parser.add_argument('--ego',
                    help='simulate an ego together with the nonegos')
parser.add_argument('--weather', default = 'CloudySunset')
parser.add_argument('--spline_degree', default=3, type=int)
parser.add_argument('--max_parameters_size', default=50, type=int)
parser.add_argument('--max_mutations_per_iteration', default=4, type=int)
parser.add_argument('--arrival_distance', default=4., type=float)
args = parser.parse_args()

# Default maximum:
maxSteps = 400
# Set maximum duration if requested:
if args.maxSteps:
    maxSteps = args.maxSteps
elif args.maxSeconds:
    maxSteps = args.maxSeconds*args.timestep

in_corpus = seed_corpus.SeedCorpus([])
in_corpus.load(args.in_corpus)

# Fuzzer configs
config = {}
config['maxSteps'] = maxSteps
config['timestep'] = args.timestep
config['weather'] = args.weather
config['arrival_distance'] = args.arrival_distance
config['spline_degree'] = args.spline_degree
config['max_parameters_size'] = args.max_parameters_size
config['max_mutations_per_iteration'] = args.max_mutations_per_iteration
config['max_nonegos'] = args.max_nonegos
config['iterations'] = args.iterations
config['carla_map'] = in_corpus.config['carla_map']
config['map'] = in_corpus.config['map']
config['intersection'] = in_corpus.config['intersection']
config['traffic_rules'] = in_corpus.config['traffic_rules']

# Instantiate a fuzzer
mutator = mutators.RandomMutator(config)
coverage = coverages.PredicateNameCoverage(config=config)
scheduler = schedulers.PriorityScheduler(config=config)
fuzzer = fuzzers.ModularFuzzer(corpus=in_corpus,
                               config=config,
                               coverage=coverage,
                               mutator=mutator,
                               scheduler=scheduler)

# Run the fuzzer
fuzzer.run()
# Save the resulting seed corpus
fuzzer.save(args.out_corpus)
