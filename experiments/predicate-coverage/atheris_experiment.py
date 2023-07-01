#!/usr/bin/env python3.8

import sys
import jsonpickle
from pathlib import Path
import atheris
# with atheris.instrument_imports():
#   from scenariogen.core.scenario import Scenario
#   import scenariogen.core.seed

# This project
from scenariogen.core.errors import EgoCollisionError, InvalidSeedError
from scenariogen.core.scenario import Scenario
import scenariogen.core.seed
from scenariogen.core.mutators import RandomMutator, MutationError

seed_mutator = RandomMutator({'max_parameters_size': 50,
                              'max_mutations_per_iteration': 1
                              },
                              0)

#--- Experiment constants ---
iterations = 2

config = {
  'timestep': 0.05,
  'no_render': True,
  'weather': 'CloudySunset',
  'arrival_distance': 4,
  'stop_speed_threshold': 0.5,
  'closedLoop': True,
  'ego_module': 'experiments.agents.followLane',
  'simulator': 'newtonian',
}

#-----------------------------------
#---------- Default config ---------
#-----------------------------------
iteration = 0
# @atheris.instrument_func
def PureAtheris(input_bytes):
  global iteration
  iteration += 1

  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_str = fdp.ConsumeUnicode(sys.maxsize)
  input_str = '{' + input_str

  # Skip mutant if structurally invalid.
  try:
    seed = jsonpickle.decode(input_str)
  except Exception as e:
    print(e)
    return

  if not scenariogen.core.seed.is_valid_seed(seed):
    print('Invalid seed.')
    return
  
  seconds = seed.trajectories[0].ctrlpts[-1][2]
  config.update({
            'steps': seconds // config['timestep'],
            })

  try:
    sim_result = Scenario(seed).run(config)
  except InvalidSeedError:
      print('InvalidSeedError, discarding the seed.')
  except EgoCollisionError:
      print('Ego collision. Saving the seed to corpus...')
      with open(f'experiments/predicate-coverage/corpus_atheris/{iteration}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))

#-----------------------------------
#---------- Grammar-aware ----------
#-----------------------------------
# We provide custom mutators that guarantee valid-seed in, valid-seed out
def SeedMutator(data, max_size, seed):
  fdp = atheris.FuzzedDataProvider(data)
  input_str = fdp.ConsumeUnicode(sys.maxsize)
  input_str = '{' + input_str
  print(input_str)

  # Skip mutant if structurally invalid.
  try:
    decoded = jsonpickle.decode(input_str)
  except Exception as e:
    print(e)
    return
  mutant = seed_mutator.mutate(decoded)
  return bytes(jsonpickle.encode(mutant), encoding='utf-8')

iteration = 0
@atheris.instrument_func
def GrammarBased(input_bytes):
  global iteration
  iteration += 1

  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_str = fdp.ConsumeUnicode(sys.maxsize)
  input_str = '{' + input_str

  # Skip mutant if structurally invalid.
  try:
    seed = jsonpickle.decode(input_str)
  except Exception as e:
    print(e)
    return

  if not scenariogen.core.seed.is_valid_seed(seed):
    print('Invalid seed:')
    # print(seed)
    return
  
  seconds = seed.trajectories[0].ctrlpts[-1][2]
  config.update({
            'steps': seconds // config['timestep'],
            })

  try:
    sim_result = Scenario(seed).run(config)
  except InvalidSeedError:
      print('InvalidSeedError, discarding the seed.')
  except EgoCollisionError:
      print('Ego collision. Saving the seed to corpus...')
      with open(f'experiments/predicate-coverage/corpus_atheris/{iteration}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))

  return


def main():
  # atheris.instrument_all()

  # fuzzer_config = {
  #   'atheris_runs': iterations,
  #   }
  # atheris.Setup(sys.argv, PureAtheris, **pure_config)
  # atheris.Fuzz()

  # Grammar-aware setup
  atheris_config = {
    'custom_mutator': SeedMutator,
  }
  libfuzzer_config = [f'-atheris_runs={iterations}',
                      f'-max_len={100000}',
                    ]
  atheris.Setup(sys.argv + libfuzzer_config, GrammarBased, **atheris_config)
  atheris.Fuzz()

if __name__ == "__main__":
  main()

