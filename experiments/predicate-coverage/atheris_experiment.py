#!/usr/bin/env python3.8

import sys
import jsonpickle

import atheris
with atheris.instrument_imports():
  import scenariogen.core.scenario as scenario
  import scenariogen.core.seed as seed

# Scenario config
in_corpus_folder = 'experiments/initial_seeds'
with open(f'{in_corpus_folder}/config.json', 'r') as f:
  config = jsonpickle.decode(f.read())

@atheris.instrument_func
def TestVUT(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_str = fdp.ConsumeUnicode(sys.maxsize)

  # Skip mutant if structurally invalid.
  # TODO Alternatively, we can do grammar-based fuzzing to avoid structurally invalid seeds
  try:
    seed = jsonpickle.decode(input_str)
  except Exception as e:
    return
  
  assert isinstance(seed, seed.Seed)

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

atheris.Setup(sys.argv, TestVUT) # TODO assign the setup parameters here instead of passing from CLI
atheris.Fuzz()
