#!/usr/bin/env python3.8

# System Under Test:
#  A VUT (Vehicle Under Test) following a predefined route
#
# SUT input:
#  seed json file
# 
# SUT output:
#  success/failure (exit code, exceptions)
#
# Coverage criteria:
#    Coverage is a property of a set of seeds (i.e. a seed corpus),
#    in our case, the set of predicates that are covered
#  Option 1:
#    predicate coverage is measured after the fuzzer is done.
#    The fuzzer may internally use other coverage criteria such as code coverage
#  Option 2:
#    the fuzzer takes a coverage function as an input and
#    chooses samples accordingly to maximize the given coverage criteria

# Experiment hypothesis:
#  None of the available fuzzers acheive good predicate coverage

# Available fuzzers:
#  Atheris
#  Pythonfuzz
#  PyJFuzz, gramfuzz
#  fuzzing

# Pythonfuzz
# from pythonfuzz.main import PythonFuzz

# @PythonFuzz
# def fuzz(buf):
#     try: 
#         string = buf.decode("ascii")
#         parser = HTMLParser()
#         parser.feed(string)
#     except UnicodeDecodeError:
#         pass


# if __name__ == '__main__':
#     fuzz()




#  Atheris
import atheris
import sys
import json

with atheris.instrument_imports():
  from src.scenariogen.core.scenario import Scenario

in_corpus_path = '../initial_seeds/3way-stop.json'
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
