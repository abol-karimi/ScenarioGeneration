import sys
import jsonpickle
from pathlib import Path
import atheris
from dataclasses import dataclass
from typing import Dict, Any, Set
import time

# This project
import scenariogen.core.fuzz_input as seed
from src.scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError, InvalidFuzzInputError
from scenariogen.core.scenario import Scenario
from scenariogen.core.fuzz_input import validate_input
from scenariogen.core.mutators import StructureAwareMutator
from scenariogen.core.crossovers import StructureAwareCrossOver

#----------------------------------------------
#---------- mutator's wrapper ----------
#----------------------------------------------
class MutatorCallback:
  """ Mutator callback wrapper passed to atheris.
  """
  def __init__(self, mutator):
    self.mutator = mutator
  
  def __call__(self, *args: Any, **kwds: Any):
    data = args[0]

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
      validate_input(decoded)
    except InvalidFuzzInputError as err:
      print(f'Invalid input to mutator: {err}')
      raise err

    mutant = self.mutator.mutate(decoded) # valid in, valid out

    try:
      validate_input(mutant)
    except InvalidFuzzInputError as err:
      print(f'Invalid mutant: {err}')
      raise err

    return bytes(jsonpickle.encode(mutant), encoding='utf-8')

#------------------------------------------
#---------- cross-over's wrapper ----------
#------------------------------------------
class CrossOverCallback:
  """Crossover callback wrapper passed to atheris."""
  def __init__(self, crossOver):
    self.crossOver = crossOver

  def __call__(self, *args: Any, **kwds: Any):
    data1, data2 = args[0], args[1]

    fdp1 = atheris.FuzzedDataProvider(data1)
    input_str1 = fdp1.ConsumeUnicode(sys.maxsize)
    input_str1 = '{' + input_str1

    # Skip seed if structurally invalid.
    try:
      decoded1 = jsonpickle.decode(input_str1)
      validate_input(decoded1)
    except InvalidFuzzInputError as err:
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
      validate_input(decoded2)
    except InvalidFuzzInputError as err:
      print(f'Invalid input to crossover: {err}')
      raise err
    except Exception as e:
      print(f'{e} ...in decoding the seed:')
      print(input_str2)
      return

    crossover = self.crossOver.cross_over(decoded1, decoded2) # valid in, valid out

    try:
      validate_input(crossover)
    except InvalidFuzzInputError as err:
      print(f'Invalid crossover: {err}')
      raise err

    return bytes(jsonpickle.encode(crossover), encoding='utf-8')

#-----------------------------------------------------------
#---------- SUT wrapper to make an Atheris target ----------
#-----------------------------------------------------------
class SUTCallback:
  def __init__(self, config):
    self.config = config
    self.SUT_config = config['SUT_config']
    self.ego_collisions_folder = f"{config['output_folder']}/ego-collisions"
    self.coverage_folder = f"{config['output_folder']}/coverage"
    self.coverage_sum = set()
    self.iteration = 0

  @atheris.instrument_func
  def __call__(self, *args: Any, **kwds: Any) -> Any:
    self.iteration += 1
    print(f'--------------Iteration: {self.iteration}--------------')

    input_bytes = args[0]

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
      validate_input(seed)
    except InvalidFuzzInputError as err:
      print(err.msg)
      return
    
    seconds = seed.timings[0].ctrlpts[-1][0]
    self.SUT_config.update({
              'steps': int(seconds // self.SUT_config['timestep']),
              })

    try:
      sim_result = Scenario(seed).run(self.SUT_config)
    except NonegoNonegoCollisionError as err:
        print(f'Collision between nonegos {err.nonego} and {err.other}, discarding the fuzz-input.')
    except EgoCollisionError as err:
        print(f'Ego collided with {err.other.name}. Saving the seed to corpus...')
        with open(f'{self.ego_collisions_folder}/{self.iteration}.json', 'w') as f:
          f.write(jsonpickle.encode(seed, indent=1))
    else: 
      coverage_space = sim_result.records['coverage_space'] # TODO for performance: do it only once
      coverage = sim_result.records['coverage']
      if coverage.issubset(self.coverage_sum):
        print('Input did not yield new coverage.')
      else:
        print('Found a seed increasing predicate-coverage! Adding it to corpus...')
        with open(f'{self.coverage_folder}/{self.iteration}.json', 'w') as f:
          f.write(jsonpickle.encode(seed))
        self.coverage_sum.update(coverage)
        print('Coverage ratio:', len(self.coverage_sum)/len(coverage_space))
        print('Coverage gap:', coverage_space-self.coverage_sum)

#------------------------------------
#---------- Atheris wrapper ---------
#------------------------------------
class AtherisFuzzer:
  def __init__(self, config):
    self.config = config
    self.output_path = Path(config['output_folder'])
    self.mutator = MutatorCallback(config['mutator'])
    self.crossOver = CrossOverCallback(config['crossOver'])

    self.libfuzzer_config = [f"-max_total_time={config['max_total_time']}",
                             f"-max_len={config['max_seed_length']}",
                             (self.output_path/'atheris').as_posix(),
                             config['seeds_folder'],
                            ]
    self.SUT = SUTCallback(config)

  def run(self):
    state_file = self.output_path/'fuzzer_state.json'
    if state_file.is_file():
      #resume
      with open(state_file, 'r') as f:
        fuzzer_state = jsonpickle.decode(f.read())
        self.load_state(fuzzer_state)
    else:
      # start
      (self.output_path/'atheris').mkdir(parents=True, exist_ok=True)
      (self.output_path/'coverage').mkdir(parents=True, exist_ok=True)
      (self.output_path/'ego-collisions').mkdir(parents=True, exist_ok=True)

    # setup autosave
    # TODO

    # run
    atheris.Setup(sys.argv + self.libfuzzer_config,
                  self.SUT,
                  custom_mutator=self.mutator,
                  custom_crossover=self.crossOver
                  )
    atheris.Fuzz()    
  
  def save_state(self):
    mutator_state = self.mutator.get_state()
    crossOver_state = self.crossOver.get_state()
    # atheris_state = ?
   

  def load_state(self):
    pass