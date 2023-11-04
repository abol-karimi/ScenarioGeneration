import sys
import jsonpickle
from pathlib import Path
import atheris
from typing import Any
from multiprocessing import Process, Queue

# This project
from src.scenariogen.core.scenario import Scenario
from scenariogen.core.errors import InvalidFuzzInputError
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
    decoded1 = jsonpickle.decode(input_str1)

    fdp2 = atheris.FuzzedDataProvider(data2)
    input_str2 = fdp2.ConsumeUnicode(sys.maxsize)
    input_str2 = '{' + input_str2
    decoded2 = jsonpickle.decode(input_str2)

    crossover = self.crossOver.cross_over(decoded1, decoded2) # valid in, valid out

    return bytes(jsonpickle.encode(crossover), encoding='utf-8')

#-----------------------------------------------------------
#---------- SUT wrapper to make an Atheris target ----------
#----------------------------------------------------------- 
class SUTCallback:
  def __init__(self, config, crashesOut):
    self.config = config # SUT parameters (not inputs)
    self.crashesOut = crashesOut # report crash-causing fuzz inputs

  def __call__(self, *args: Any, **kwds: Any) -> Any:
    input_bytes = args[0]

    if len(input_bytes) == 0:
      print('input_bytes is empty!')
      return

    fdp = atheris.FuzzedDataProvider(input_bytes)
    input_str = fdp.ConsumeUnicode(sys.maxsize)
    input_str = '{' + input_str

    fuzz_input = jsonpickle.decode(input_str)
    try:
      Scenario(fuzz_input).run(self.config)
    except Exception as e:
      print(e)
      # self.crashesOut.put((fuzz_input, e))


#------------------------------------
#---------- Atheris wrapper ---------
#------------------------------------
class AtherisFuzzer:
  def __init__(self, config):
    self.config = config
    self.output_path = Path(config['output_folder'])
    self.mutator = MutatorCallback(config['mutator'])
    self.crossOver = CrossOverCallback(config['crossOver'])
    self.SUT_crashes = None #Queue()
    self.libfuzzer_config = [f"-atheris_runs={config['atheris_runs']}",
                             f"-artifact_prefix={self.output_path/'bugs'}/",
                             f"-max_len={config['max_seed_length']}",
                             f"-timeout=120", # scenarios taking more than 2 minutes are considered as bugs
                             f"-report_slow_units=60", # scenarios taking more than a minute are considered slow
                             f"-rss_limit_mb=16384",
                             (self.output_path/'fuzz-inputs').as_posix(),
                             config['seeds_folder'],
                            ]
    self.SUT = SUTCallback(config['SUT_config'], self.SUT_crashes)

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
    SUT_crashes = []
    # while not self.SUT_crashes.empty():
    #   SUT_crashes.append(self.SUT_crashes.get())

    state = {
      'SUT_crashes': tuple(SUT_crashes),
      'mutator_state': self.mutator.get_state(),
      'crossOver_state': self.crossOver.get_state()
      }
    return state
   
  def set_state(self, state):
    self.mutator.set_state(state['mutator_state'])
    self.crossOver.set_state(state['crossOver_state'])