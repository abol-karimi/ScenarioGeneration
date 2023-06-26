#!/usr/bin/env python3.8

import sys
import jsonpickle

import atheris
with atheris.instrument_imports():
  from scenariogen.core.scenario import Scenario
  import scenariogen.core.seed as seed

# Experiment constants
iterations = 10000

# Scenario config
in_corpus_folder = 'experiments/initial_seeds/3way-stop'
with open(f'{in_corpus_folder}/config.json', 'r') as f:
  scenario_config = jsonpickle.decode(f.read())

#-----------------------------------
#---------- Default config ---------
#-----------------------------------
@atheris.instrument_func
def PureAtheris(input_bytes):
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
    sim_result = Scenario(scenario_config, seed).run()
  except Exception as e:
    print(e)
    pass
  # except EgoCollisionError:
  #   # add seed to the corpus
  #   pass

fuzzer_config = {'atheris_runs': iterations,
          }
atheris.Setup(sys.argv, PureAtheris, **fuzzer_config)
atheris.Fuzz()

#-----------------------------------
#---------- Grammar-aware ----------
#-----------------------------------
# We provide custom mutators that 
@atheris.instrument_func
def GrammarBased(input_bytes):
  return


