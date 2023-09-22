import sys
import jsonpickle
from pathlib import Path
import atheris
from typing import Any
from multiprocessing import Process, Queue

# This project
from src.scenariogen.core.scenario import Scenario
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError, InvalidFuzzInputError
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
  def __init__(self, config, comm):
    self.config = config
    self.comm = comm
    self.SUT_config = config['SUT_config']
    self.ego_collisions_folder = f"{config['output_folder']}/ego-collisions"
    self.predicate_coverage_folder = f"{config['output_folder']}/predicate-coverage"
    self.coverage_sum = set()
    self.initial_iteration = 0
    self.current_iteration = 0
  
  def get_state(self):
    return {'coverage_sum': self.coverage_sum,
            'iteration': self.current_iteration}
  
  def set_state(self, state):
    self.coverage_sum = state['coverage_sum']
    self.initial_iteration = state['iteration']
    self.current_iteration = self.initial_iteration

  @atheris.instrument_func
  def __call__(self, *args: Any, **kwds: Any) -> Any:
    self.current_iteration += 1
    print(f'--------------Iteration: {self.current_iteration}--------------')

    input_bytes = args[0]

    if len(input_bytes) == 0:
      print('input_bytes is empty!')
      return

    fdp = atheris.FuzzedDataProvider(input_bytes)
    input_str = fdp.ConsumeUnicode(sys.maxsize)
    input_str = '{' + input_str

    # Skip mutant if structurally invalid.
    try:
      fuzz_input = jsonpickle.decode(input_str)
    except Exception as e:
      print(f'{e} ...in decoding the fuzz_input: ')
      print(input_str)
      exit(1)

    try:
      validate_input(fuzz_input)
    except InvalidFuzzInputError as err:
      print(err.msg)
      exit(1)
    
    seconds = fuzz_input.timings[0].ctrlpts[-1][0]
    self.SUT_config.update({
              'steps': int(seconds // self.SUT_config['timestep']),
              })

    try:
      sim_result = Scenario(fuzz_input).run(self.SUT_config)
      coverage_space = sim_result.records['coverage_space'] # TODO for performance: do it only once
      coverage = sim_result.records['coverage']
    except NonegoNonegoCollisionError as err:
      print(f'Collision between nonegos {err.nonego} and {err.other}! We skip predicate-coverage computation.')
    except EgoCollisionError as err:
      print(f'Ego collided with {err.other}. We save the fuzz input to the ego-collisions corpus.')
      with open(f'{self.ego_collisions_folder}/{self.current_iteration}.json', 'w') as f:
        f.write(jsonpickle.encode(fuzz_input, indent=1))
    # except Exception as e:
    #   print(e)
    else: 
      if coverage.issubset(self.coverage_sum):
        print('Input did not yield new coverage.')
      else:
        print('Found a fuzz-input increasing predicate-coverage! Adding it to predicate-coverage corpus...')
        with open(f'{self.predicate_coverage_folder}/{self.current_iteration}.json', 'w') as f:
          f.write(jsonpickle.encode(fuzz_input))
        self.coverage_sum.update(coverage)
        print('Coverage ratio:', len(self.coverage_sum)/len(coverage_space))
        print('Coverage gap:', coverage_space-self.coverage_sum)
    
    if self.current_iteration == self.initial_iteration + self.config['atheris_runs']:
      self.comm.put(self.get_state())

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
                             (self.output_path/'code-coverage').as_posix(),
                             config['seeds_folder'],
                            ]
    self.comm = Queue(maxsize=1)
    self.SUT = SUTCallback(self.config, self.comm)

  def run(self):
    state_file = self.output_path/'fuzzer_state.json'
    if state_file.is_file(): #resume
      with open(state_file, 'r') as f:
        fuzzer_state = jsonpickle.decode(f.read())
        self.load_state(fuzzer_state)
    else: # start
      (self.output_path/'code-coverage').mkdir(parents=True, exist_ok=True)
      (self.output_path/'predicate-coverage').mkdir(parents=True, exist_ok=True)
      (self.output_path/'ego-collisions').mkdir(parents=True, exist_ok=True)

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
    self.SUT.set_state(self.comm.get())
  
  def save_state(self):
    with open(self.output_path/'fuzzer_state.json', 'w') as f:
      f.write(jsonpickle.encode({
        'SUT_state': self.SUT.get_state(),
        'mutator_state': self.mutator.get_state(),
        'crossOver_state': self.crossOver.get_state()
      }))
   
  def load_state(self, state):
    self.SUT.set_state(state['SUT_state'])
    self.mutator.set_state(state['mutator_state'])
    self.crossOver.set_state(state['crossOver_state'])