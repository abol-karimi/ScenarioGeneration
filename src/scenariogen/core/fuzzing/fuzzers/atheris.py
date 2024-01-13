import sys
import jsonpickle
import pickle
from pathlib import Path
from typing import Any
from multiprocessing import Process
import hashlib
import atheris
from scenic.core.simulators import SimulationCreationError

# This project
from scenariogen.core.scenario import Scenario
from scenariogen.core.errors import InvalidFuzzInputError, EgoCollisionError
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

    decoded = jsonpickle.decode(input_str)

    mutant = self.mutator.mutate(decoded) # valid in, valid out

    return bytes(jsonpickle.encode(mutant, indent=1), encoding='utf-8')

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
    decoded1 = jsonpickle.decode(input_str1)

    fdp2 = atheris.FuzzedDataProvider(data2)
    input_str2 = fdp2.ConsumeUnicode(sys.maxsize)
    input_str2 = '{' + input_str2
    decoded2 = jsonpickle.decode(input_str2)

    crossover = self.crossOver.cross_over(decoded1, decoded2) # valid in, valid out

    return bytes(jsonpickle.encode(crossover, indent=1), encoding='utf-8')

#-----------------------------------------------------------
#---------- SUT wrapper to make an Atheris target ----------
#----------------------------------------------------------- 
class SUTCallback:
  def __init__(self, config):
    self.config = config # SUT parameters (not inputs)

  def __call__(self, *args: Any, **kwds: Any) -> Any:
    input_bytes = args[0]

    if len(input_bytes) == 0:
      print('input_bytes is empty!')
      return
    
    fuzz_input = jsonpickle.decode(input_bytes.decode('utf-8'))
    sim_result = None
    try:
      sim_result = Scenario(fuzz_input).run(self.config)
    except SimulationCreationError as e:
      print(f'Exception in SUTCallback: {e}')
    finally:
      if sim_result:
        coverage = sim_result.records['coverage']
        events = [e.simplified() for e in sim_result.records['events']]
      else:
        coverage = None
        events = None

    # Save coverage results to disk
    sha1 = hashlib.sha1(input_bytes).hexdigest()
    with open(Path(self.config['output_folder'])/f'coverages/{sha1}', 'w') as f:
      f.write(jsonpickle.encode(coverage, indent=1))
    with open(Path(self.config['output_folder'])/f'events/{sha1}', 'w') as f:
          f.write(jsonpickle.encode(events, indent=1))      



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
                             f"-artifact_prefix={self.output_path/'bugs'}/",
                             f"-max_len={config['max_seed_length']}",
                             f"-timeout=300", # scenarios taking more than 5 minutes are considered as bugs
                             f"-report_slow_units=120", # scenarios taking more than 2 minutes are considered slow
                             f"-rss_limit_mb=16384",
                             (self.output_path/'fuzz-inputs').as_posix(),
                             config['seeds_folder'],
                            ]
    self.SUT = SUTCallback({**config['SUT_config'],
                            **config['coverage_config'],
                            'output_folder': config['output_folder'],
                            })

  def run(self, atheris_state=None):
    if atheris_state: # resume
      self.set_state(atheris_state)

    def target():
      atheris.instrument_all()
      atheris.Setup(sys.argv + self.libfuzzer_config,
                self.SUT,
                custom_mutator=self.mutator,
                custom_crossover=self.crossOver
                )
      atheris.Fuzz()

    p = Process(target=target, name='Atheris', args=())
    p.start()
    p.join()

    return self.get_state()
  
  def get_state(self):
    state = {
      'mutator_state': self.mutator.get_state(),
      'crossOver_state': self.crossOver.get_state()
      }
    return state

  def set_state(self, state):
    self.mutator.set_state(state['mutator_state'])
    self.crossOver.set_state(state['crossOver_state'])