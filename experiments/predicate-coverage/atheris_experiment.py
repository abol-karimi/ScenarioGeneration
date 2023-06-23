#!/usr/bin/env python3.8

import sys
import json

import atheris
with atheris.instrument_imports():
  import scenariogen.core.scenario as scenario
  import scenariogen.core.seed_corpus as seed_corpus

in_corpus_path = 'experiments/initial_seeds/3way-stop.json'
in_corpus = seed_corpus.SeedCorpus([])
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
config['ego'] = True

@atheris.instrument_func
def TestVUT(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  original = fdp.ConsumeUnicode(sys.maxsize)

  # Skip mutant if structurally invalid.
  # TODO Alternatively, we can do grammar-based fuzzing to avoid structurally invalid seeds
  try:
    json_data = json.loads(original)
    seed = json.load(json_data)
  except Exception as e:
    return
  if not seed.is_valid():
    return

  try:
    sim_result = scenario.Scenario(config, seed).run()
  except Exception as e:
    print(e)
    pass
  # except EgoCollisionError:
  #   # add seed to the corpus
  #   pass

atheris.Setup(sys.argv, TestVUT)
atheris.Fuzz()
