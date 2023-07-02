#!/usr/bin/env python3.8

import sys
import jsonpickle
from pathlib import Path
import atheris
# with atheris.instrument_imports():
#   from scenariogen.core.scenario import Scenario
#   import scenariogen.core.seed

# This project
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError, InvalidSeedError
from scenariogen.core.scenario import Scenario
import scenariogen.core.seed
from scenariogen.core.seed import validate_seed
from scenariogen.core.mutators import RandomMutator, MutationError

seed_mutator = RandomMutator({'max_parameters_size': 50,
                              'max_mutations_per_iteration': 1
                              },
                              0)

#-----------------------------------
#---------- Default config ---------
#-----------------------------------
iteration = 0
# @atheris.instrument_func
def PureAtheris(input_bytes):
  global scenario_config
  global iteration
  iteration += 1

  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_str = fdp.ConsumeUnicode(sys.maxsize)
  input_str = '{' + input_str

  # Skip mutant if structurally invalid.
  try:
    seed = jsonpickle.decode(input_str)
  except Exception as e:
    print(f'Iteration {iteration}: {e}')
    return

  try:
    validate_seed(seed)
  except InvalidSeedError as err:
    print(f'Iteration {iteration}: {err.msg}')
    return
  
  seconds = seed.trajectories[0].ctrlpts[-1][2]
  scenario_config.update({
            'steps': seconds // scenario_config['timestep'],
            })

  try:
    sim_result = Scenario(seed).run(scenario_config)
  except NonegoNonegoCollisionError as err:
      print(f'Iteration {iteration}: Collision between nonegos {err.nonego} and {err.other}, discarding the seed.')
  except EgoCollisionError as err:
      print(f'Iteration {iteration}: Ego collided with {err.other.name}. Saving the seed to corpus...')
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

  # Skip mutant if structurally invalid.
  try:
    decoded = jsonpickle.decode(input_str)
  except Exception as e:
    print(f'Iteration {iteration}: {e}')
    print(f'...in decoding the seed: ')
    print(input_str)
    return

  try:
    validate_seed(decoded)
  except InvalidSeedError as err:
    print(f'Iteration {iteration}, invalid input to mutator: {err}')

  mutant = seed_mutator.mutate(decoded)

  try:
    validate_seed(mutant)
  except InvalidSeedError as err:
    print(f'Iteration {iteration}, invalid mutant: {err}')

  return bytes(jsonpickle.encode(mutant), encoding='utf-8')

iteration = 0
@atheris.instrument_func
def GrammarBased(input_bytes):
  global scenario_config
  global iteration
  iteration += 1

  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_str = fdp.ConsumeUnicode(sys.maxsize)
  input_str = '{' + input_str

  # Skip mutant if structurally invalid.
  try:
    seed = jsonpickle.decode(input_str)
  except Exception as e:
    print(f'Iteration {iteration}: {e}')
    print(f'...in decoding the seed: ')
    print(input_str)
    return

  try:
    validate_seed(seed)
  except InvalidSeedError as err:
    print(err.msg)
    return
  
  seconds = seed.trajectories[0].ctrlpts[-1][2]
  scenario_config.update({
            'steps': seconds // scenario_config['timestep'],
            })

  try:
    sim_result = Scenario(seed).run(scenario_config)
  except NonegoNonegoCollisionError as err:
      print(f'Collision between nonegos {err.nonego} and {err.other}, discarding the seed.')
  except EgoCollisionError as err:
      print(f'Ego collided with {err.other.name}. Saving the seed to corpus...')
      with open(f'experiments/predicate-coverage/corpus_atheris/{iteration}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))

  return

def experiment(atheris_config={}, iterations=1, target=None):
  # atheris.instrument_all()

  libfuzzer_config = [f'-atheris_runs={iterations}',
                      f'-max_len={100000}',
                      f'experiments/predicate-coverage/corpus_atheris',
                      f'experiments/initial_seeds',
                    ]
  atheris.Setup(sys.argv + libfuzzer_config, target, **atheris_config)
  atheris.Fuzz()

if __name__ == "__main__":
  #--- Experiment constants ---
  iterations = 4

  scenario_config = {
    'timestep': 0.05,
    'no_render': True,
    'weather': 'CloudySunset',
    'arrival_distance': 4,
    'stop_speed_threshold': 0.5,
    'closedLoop': True,
    'ego_module': 'experiments.agents.followLane',
    'simulator': 'newtonian',
  }
  atheris_config = {
    'custom_mutator': SeedMutator,
  }
  experiment(atheris_config=atheris_config, iterations=iterations, target=GrammarBased)

