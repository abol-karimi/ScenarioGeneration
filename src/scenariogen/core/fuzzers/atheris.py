import sys
import jsonpickle
from pathlib import Path
import atheris
from typing import Any
from multiprocessing import Process, Queue

# This project
from src.scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError, InvalidFuzzInputError
from scenariogen.core.scenario import Scenario
from scenariogen.core.fuzz_input import validate_input

#----------------------------------------------
#---------- mutator's wrapper ----------
#----------------------------------------------
class MutatorCallback:
  """ Mutator callback wrapper passed to atheris.
  """
  def __init__(self, mutator):
    self.mutator = mutator
  
  def get_state(self):
    return self.mutator.get_state()
  
  def set_state(self, state):
    self.mutator.set_state(state)

  def __call__(self, *args: Any, **kwds: Any):
    data = args[0]

    fdp = atheris.FuzzedDataProvider(data)
    input_str = fdp.ConsumeUnicode(sys.maxsize)
    input_str = '{' + input_str

    # Skip mutant if structurally invalid.
    try:
      decoded = jsonpickle.decode(input_str)
    except Exception as e:
      print(f'{e} ...in decoding the fuzz_input:')
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

  def get_state(self):
    return self.crossOver.get_state()

  def set_state(self, state):
    self.crossOver.set_state(state)
  
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
    self.config = config # SUT parameters (not inputs)
  
  @atheris.instrument_func
  def __call__(self, *args: Any, **kwds: Any) -> Any:
    input_bytes = args[0]

    if len(input_bytes) == 0:
      print('input_bytes is empty!')
      return

    fdp = atheris.FuzzedDataProvider(input_bytes)
    input_str = fdp.ConsumeUnicode(sys.maxsize)
    input_str = '{' + input_str

    fuzz_input = jsonpickle.decode(input_str)
    Scenario(fuzz_input).run(self.config)
    print(f'Simulation of SUT finished.')


#------------------------------------
#---------- Atheris wrapper ---------
#------------------------------------
class AtherisFuzzer:
  def __init__(self, config):
    self.config = config
    self.output_path = Path(config['output_folder'])
    self.mutator = MutatorCallback(config['mutator'])
    self.crossOver = CrossOverCallback(config['crossOver'])

    self.libfuzzer_config = [f"-atheris_runs={config['atheris_runs']}",
                             f"-max_len={config['max_seed_length']}",
                             f"-rss_limit_mb=4096",
                             (self.output_path/'fuzz-inputs').as_posix(),
                             config['seeds_folder'],
                            ]
    self.SUT = SUTCallback(self.config['SUT_config'])

  def run(self):
    state_file = self.output_path/'fuzzer_state.json'
    if state_file.is_file(): #resume
      with open(state_file, 'r') as f:
        fuzzer_state = jsonpickle.decode(f.read())
        self.load_state(fuzzer_state)
    else: # start
      (self.output_path/'fuzz-inputs').mkdir(parents=True, exist_ok=True)
      (self.output_path/'bugs').mkdir(parents=True, exist_ok=True)

    def _run():
      atheris.Setup(sys.argv + self.libfuzzer_config,
                    self.SUT,
                    custom_mutator=self.mutator,
                    custom_crossover=self.crossOver
                    )
      atheris.Fuzz()

    p = Process(target=_run, args=())
    p.start()
    p.join()
  
  def save_state(self):
    with open(self.output_path/'fuzzer_state.json', 'w') as f:
      f.write(jsonpickle.encode({
        'mutator_state': self.mutator.get_state(),
        'crossOver_state': self.crossOver.get_state()
      }))
   
  def load_state(self, state):
    self.mutator.set_state(state['mutator_state'])
    self.crossOver.set_state(state['crossOver_state'])