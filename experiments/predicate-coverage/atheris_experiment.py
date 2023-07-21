#!/usr/bin/env python3.8

import sys
import jsonpickle
from pathlib import Path
import atheris

# This project
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError, InvalidSeedError
from scenariogen.core.scenario import Scenario
from scenariogen.core.seed import validate_seed
from scenariogen.core.mutators import StructureAwareMutator
from scenariogen.core.crossovers import StructureAwareCrossOver
from scenariogen.core.coverages import PredicateNameCoverage

#----------------------------------------------
#---------- custom mutator's wrapper ----------
#----------------------------------------------
# Custom mutators can be plugged in via the global variable mutator
def custom_mutator_wrapper(data, max_size, seed):
  global mutator

  fdp = atheris.FuzzedDataProvider(data)
  input_str = fdp.ConsumeUnicode(sys.maxsize)
  input_str = '{' + input_str

  # Skip mutant if structurally invalid.
  try:
    decoded = jsonpickle.decode(input_str)
  except Exception as e:
    print(f'{e} ...in decoding the seed:')
    print(input_str)
    return

  try:
    validate_seed(decoded)
  except InvalidSeedError as err:
    print(f'Invalid input to mutator: {err}')
    raise err

  mutant = mutator.mutate(decoded) # valid in, valid out

  try:
    validate_seed(mutant)
  except InvalidSeedError as err:
    print(f'Invalid mutant: {err}')
    raise err

  return bytes(jsonpickle.encode(mutant), encoding='utf-8')

#-------------------------------------------------
#---------- custom cross-over's wrapper ----------
#-------------------------------------------------
def custom_crossover_wrapper(data1, data2, max_size, seed):
  global crossOver

  fdp1 = atheris.FuzzedDataProvider(data1)
  input_str1 = fdp1.ConsumeUnicode(sys.maxsize)
  input_str1 = '{' + input_str1

  # Skip seed if structurally invalid.
  try:
    decoded1 = jsonpickle.decode(input_str1)
    validate_seed(decoded1)
  except InvalidSeedError as err:
    print(f'Invalid input to crossover: {err}')
    raise err
  except Exception as e:
    print(f'{e} ...in decoding the seed:')
    print(input_str1)
    return

  fdp2 = atheris.FuzzedDataProvider(data2)
  input_str2 = fdp2.ConsumeUnicode(sys.maxsize)
  input_str2 = '{' + input_str2
  try:
    decoded2 = jsonpickle.decode(input_str2)
    validate_seed(decoded2)
  except InvalidSeedError as err:
    print(f'Invalid input to crossover: {err}')
    raise err
  except Exception as e:
    print(f'{e} ...in decoding the seed:')
    print(input_str2)
    return

  crossover = crossOver.cross_over(decoded1, decoded2) # valid in, valid out

  try:
    validate_seed(crossover)
  except InvalidSeedError as err:
    print(f'Invalid crossover: {err}')
    raise err

  return bytes(jsonpickle.encode(crossover), encoding='utf-8')

#-----------------------------------------------------------
#---------- SUT wrapper to make an Atheris target ----------
#-----------------------------------------------------------
# Custom coverage object can be plugged in via global variable coverage_sum
@atheris.instrument_func
def SUT_target_wrapper(input_bytes):
  global experiment_name
  global scenario_config
  global coverage_sum
  global iteration
  iteration += 1

  print(f'--------------Iteration: {iteration}--------------')

  if len(input_bytes) == 0:
    print('input_bytes is empty!')
    return

  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_str = fdp.ConsumeUnicode(sys.maxsize)
  input_str = '{' + input_str

  # Skip mutant if structurally invalid.
  try:
    seed = jsonpickle.decode(input_str)
  except Exception as e:
    print(f'{e} ...in decoding the seed: ')
    print(input_str)
    return

  try:
    validate_seed(seed)
  except InvalidSeedError as err:
    print(err.msg)
    return
  
  seconds = seed.timings[0].ctrlpts[-1][1]
  scenario_config.update({
            'steps': seconds // scenario_config['timestep'],
            })

  try:
    sim_result = Scenario(seed).run(scenario_config)
  except NonegoNonegoCollisionError as err:
      print(f'Collision between nonegos {err.nonego} and {err.other}, discarding the seed.')
  except EgoCollisionError as err:
      print(f'Ego collided with {err.other.name}. Saving the seed to corpus...')
      with open(f'experiments/predicate-coverage/{experiment_name}_ego-collisions/{iteration}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))
  else: 
    coverage = PredicateNameCoverage.from_sim(sim_result)
    if coverage.is_novel_to(coverage_sum):
      print('Found a seed increading predicate-coverage! Adding it to corpus...')
      with open(f'experiments/predicate-coverage/{experiment_name}_{coverage_sum.__class__.__name__}/{iteration}.json', 'w') as f:
        f.write(jsonpickle.encode(seed))
      coverage_sum += coverage

#-----------------------------------------------------
#----------------- Experiment config -----------------
#-----------------------------------------------------
experiment_name = 'AtherisWithStructureAwareMutator'
scenario_config = {
  'timestep': 0.05,
  'render': False,
  'weather': 'CloudySunset',
  'arrival_distance': 4,
  'stop_speed_threshold': 0.5,
  'closedLoop': True,
  'ego_module': 'experiments.agents.followLane',
  'simulator': 'newtonian',
}
atheris_config = {
  'custom_mutator': custom_mutator_wrapper,
  'custom_crossover': custom_crossover_wrapper
}
# My structure-aware mutator
mutator = StructureAwareMutator(max_parameters_size=50,
                                max_mutations_per_iteration=1,
                                randomizer_seed=0)
crossOver = StructureAwareCrossOver(max_parameters_size=50,
                                    max_attempts=1,
                                    randomizer_seed=0)
corpus = {}
target=SUT_target_wrapper
iterations = 20
iteration = 0
coverage_sum = PredicateNameCoverage()
max_seed_length = 1e+6 # 1 MB
libfuzzer_config = [f'-atheris_runs={iterations}',
                    f'-max_len={max_seed_length}',
                    f'experiments/predicate-coverage/{experiment_name}_Atheris',
                    f'experiments/initial_seeds',
                  ]
Path(f'experiments/predicate-coverage/{experiment_name}_ego-collisions').mkdir(parents=True, exist_ok=True)
Path(f'experiments/predicate-coverage/{experiment_name}_Atheris').mkdir(parents=True, exist_ok=True)
Path(f'experiments/predicate-coverage/{experiment_name}_{coverage_sum.__class__.__name__}').mkdir(parents=True, exist_ok=True)
atheris.Setup(sys.argv + libfuzzer_config, target, **atheris_config)
atheris.Fuzz()