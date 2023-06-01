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
import seed_corpus
import mutators
import fuzzers
import schedulers
import coverages
from signals import SignalType
from utils import route_length

in_corpus = ''
in_corpus = seed_corpus.SeedCorpus([])
in_corpus.load(args.in_corpus)

# Fuzzer configs
config = {}
config['carla_map'] = in_corpus.config['carla_map']
config['map'] = in_corpus.config['map']
config['intersection'] = in_corpus.config['intersection']
config['traffic_rules'] = in_corpus.config['traffic_rules']
config['maxSteps'] = maxSteps
config['timestep'] = args.timestep
config['weather'] = args.weather
config['arrival_distance'] = args.arrival_distance
config['spline_degree'] = args.spline_degree
config['max_parameters_size'] = args.max_parameters_size
config['max_mutations_per_iteration'] = args.max_mutations_per_iteration
config['max_nonegos'] = args.max_nonegos
config['iterations'] = args.iterations
config['ego'] = args.ego

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
