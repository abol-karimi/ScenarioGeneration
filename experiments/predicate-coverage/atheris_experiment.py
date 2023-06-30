#!/usr/bin/env python3.8

import sys
import jsonpickle
from pathlib import Path

import atheris
with atheris.instrument_imports():
  from scenariogen.core.scenario import Scenario
  import scenariogen.core.seed

from scenariogen.core.errors import EgoCollisionError, InvalidSeedError

#--- Experiment constants ---
iterations = 10000

config = {
  'timestep': 0.05,
  'no_render': True,
  'weather': 'CloudySunset',
  'arrival_distance': 4,
  'stop_speed_threshold': 0.5,
  'closedLoop': True,
  'ego_module': 'experiments.agents.autopilot',
  'simulator': 'carla',
}

#-----------------------------------
#---------- Default config ---------
#-----------------------------------
iteration = 0
@atheris.instrument_func
def PureAtheris(input_bytes):
  global iteration
  iteration += 1

  print('Checkpoint 0.')

  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_str = fdp.ConsumeUnicode(sys.maxsize)

  input_str = '{' + input_str
  print(type(input_str))

  print('Checkpoint 1.')
  print(input_str)

  # Skip mutant if structurally invalid.
  try:
    seed = jsonpickle.decode(input_str)
  except Exception as e:
    print(e)
    return
  
  print('Checkpoint 2.')
  assert isinstance(seed, scenariogen.core.seed.Seed)

  if not scenariogen.core.seed.is_valid(seed):
    print('Invalid seed (self-check).')
    return
  
  seconds = seed.trajectories[0].ctrlpts[-1][2]
  config.update({
            'steps': seconds // config['timestep'],
            })

  print('Checkpoint 3.')
  try:
    sim_result = Scenario(seed).run(config)
  except InvalidSeedError:
      print('InvalidSeedError, discarding the seed.')
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


