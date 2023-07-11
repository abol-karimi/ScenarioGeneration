"""
Research question:
  How does the performance of open-loop and closed-loop fuzzing compare
  in terms of number of accidents for a fixed computation budget?

Open-loop fuzzing:
The set of seeds are selected without simulating the SUT.
New seeds are generated using mutation, and seeds are selected using
a scoring function on the space of inputs (to the SUT).

Closed-loop fuzzing:
The SUT is simulated on each generated seed before being selected.
New seeds are generated using mutation.
Seed selection is guided by a scoring function defined on the space of outputs (of the SUT)
which may subsume the space of inputs.
"""

#!/usr/bin/env python3.8

# Standard libraries
import argparse
import copy

# Scenic modules
from scenic.domains.driving.roads import Network

# My modules
import scenariogen.core.seed as seed
import src.scenariogen.core.mutators as mutators
import src.scenariogen.core.fuzzers as fuzzers
import src.scenariogen.core.schedulers as schedulers
import scenariogen.core.coverages as coverages
from src.scenariogen.core.signals import SignalType
from src.scenariogen.core.utils import route_length

in_corpus_path = '../initial_seeds/3way-stop.json'
in_corpus = seed.SeedCorpus([])
in_corpus.load(in_corpus_path)

# Fuzzer configs
config = {}
config['carla_map'] = in_corpus.config['carla_map']
config['map'] = in_corpus.config['map']
config['intersection'] = in_corpus.config['intersection']
config['traffic_rules'] = in_corpus.config['traffic_rules']
config['maxSeconds'] = 20 # maximum duration of a scenario, in seconds
config['timestep'] = 0.05 # simulation timestep
config['weather'] = 'CloudySunset'
config['arrival_distance'] = 4 # meters
config['spline_degree'] = 3 # cubic B-splines
config['max_parameters_size'] = 50 # maximum number of knots or control points, per spline
config['max_mutations_per_iteration'] = 4 # maximum number of times a seed can be mutated to generate a new seed
config['max_nonegos'] = 5 # maximum number of nonegos in a seed
config['iterations'] = 2 # the number of fuzzing iterations

#--------------------------------
#--- The open-loop experiment ---
#--------------------------------
config['ego'] = False

mutator = mutators.StructureAwareMutator(config)
coverage = coverages.PredicateNameCoverage(config=config)
scheduler = schedulers.PriorityScheduler(config=config)
fuzzer = fuzzers.ModularFuzzer(corpus=in_corpus,
                               config=config,
                               coverage=coverage,
                               mutator=mutator,
                               scheduler=scheduler)
fuzzer.run()
fuzzer.save(f'{in_corpus_path}_open.json')

#----------------------------------
#--- The closed-loop experiment ---
#----------------------------------
# config['ego'] = True

# mutator = mutators.StructureAwareMutator(config)
# coverage = coverages.PredicateNameCoverage(config=config)
# scheduler = schedulers.PriorityScheduler(config=config)
# fuzzer = fuzzers.ModularFuzzer(corpus=in_corpus,
#                                config=config,
#                                coverage=coverage,
#                                mutator=mutator,
#                                scheduler=scheduler)
# fuzzer.run()
# fuzzer.save(f'{in_corpus_path}_closed.json')

# Present the results







