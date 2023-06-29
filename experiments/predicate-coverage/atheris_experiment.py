#!/usr/bin/env python3.8

import sys
import jsonpickle
from pathlib import Path

import atheris
with atheris.instrument_imports():
  from scenariogen.core.scenario import Scenario
  import scenariogen.core.seed as seed

from scenariogen.core.errors import EgoCollisionError, InvalidSeedError

#--- Experiment constants ---
iterations = 10000

#-----------------------------------
#---------- Default config ---------
#-----------------------------------
iteration = 0
@atheris.instrument_func
def PureAtheris(input_bytes):
  iteration += 1

  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_str = fdp.ConsumeUnicode(sys.maxsize)

  # Skip mutant if structurally invalid.
  try:
    seed = jsonpickle.decode(input_str)
  except Exception as e:
    return
  
  assert isinstance(seed, seed.Seed)

  if not seed.is_valid():
    return

  try:
    sim_result = Scenario(seed).run()
  except InvalidSeedError:
      print('Invalid seed, discarding it.')
  except EgoCollisionError:
      print('Ego collision. Saving the seed to corpus...')
      with open(f'experiments/predicate-coverage/corpus_atheris/{iteration}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))


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


