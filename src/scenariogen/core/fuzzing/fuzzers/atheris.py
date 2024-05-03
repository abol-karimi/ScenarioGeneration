import jsonpickle
from pathlib import Path
from typing import Any
import multiprocessing
from random import Random
import atheris
import setproctitle
import logging
import sys

# This project
from scenariogen.core.fuzzing.runner import SUTRunner
import scenariogen.core.logging.server as log_server
from scenariogen.core.logging.client import configure_logger, TextIOBaseToLog


#----------------------------------------------
#---------- mutator's wrapper ----------
#----------------------------------------------
class MutatorCallback:
  """ Mutator callback wrapper passed to atheris.
  """
  def __init__(self, config):
    self.mutator = config['mutator']
    self.max_mutations_per_fuzz = config['max-mutations-per-fuzz']
    self.random = config['random']
  
  def get_state(self):
    return self.mutator.get_state()
  
  def set_state(self, state):
    self.mutator.set_state(state)

  def __call__(self, *args: Any, **kwds: Any):
    input_bytes = args[0]
    fuzz_input = jsonpickle.decode(input_bytes.decode('utf-8'))

    mutations = self.random.randint(1, self.max_mutations_per_fuzz)
    for i in range(mutations):
      fuzz_input = self.mutator.mutate(fuzz_input) # valid in, valid out

    return jsonpickle.encode(fuzz_input, indent=1).encode('utf-8')


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
    sim_result = SUTRunner.run({**self.config,
                                **fuzz_input.config,                               
                                'fuzz-input': fuzz_input,
                                })
    # check if fuzz_input is valid
    if sim_result and 'coverage' in sim_result.records:
      with open(Path(self.config['fuzz-inputs-folder'])/f'{fuzz_input.hexdigest}.json', 'wb') as f:
        f.write(input_bytes)
      with open(Path(self.config['coverages-folder'])/f'{fuzz_input.hexdigest}.json', 'w') as f:
        f.write(jsonpickle.encode(sim_result.records['coverage'], indent=1))
      
      # For debugging:
      with open(Path(self.config['events-folder'])/f'{fuzz_input.hexdigest}.json', 'w') as f:
        f.write(jsonpickle.encode(sim_result.records['events'], indent=1))

#------------------------------------
#---------- Atheris wrapper ---------
#------------------------------------
def atheris_target(config, SUT, mutator, log_queue):
  setproctitle.setproctitle('AtherisTarget')
  configure_logger(log_queue)
  logger = logging.getLogger(f'{__name__}.target')
  # capture stdout and stderr to the logs as well
  sys.stdout = TextIOBaseToLog(logger.debug)
  sys.stderr = TextIOBaseToLog(logger.warning)

  libfuzzer_config = [f"-max_total_time={config['max-total-time']}",
                      f"-artifact_prefix={Path(config['bugs-folder'])}/",
                      f"-max_len={config['max-seed-length']}",
                      f"-timeout=300", # scenarios taking more than 5 minutes are considered as bugs
                      f"-report_slow_units=120", # scenarios taking more than 2 minutes are considered slow
                      f"-rss_limit_mb=16384",
                      Path(config['atheris-output-folder']).as_posix(),
                      config['seeds-folder'],
                    ]
  atheris.instrument_all()
  atheris.Setup(libfuzzer_config,
                SUT,
                custom_mutator=mutator)
  atheris.Fuzz()


class AtherisFuzzer:
  def __init__(self, config):
    self.config = config
    self.random = Random(config['randomizer-seed'])
    self.mutator = MutatorCallback({**config['mutator-config'],
                                    'random': self.random})

    self.SUT = SUTCallback({**config['SUT-config'],
                            **config['coverage-config'],
                            'fuzz-inputs-folder': config['fuzz-inputs-folder'],
                            'coverages-folder': config['coverages-folder'],
                            'events-folder': config['events-folder'],
                            })

  def get_state(self):
    state = {
      'mutator-state': self.mutator.get_state(),
      'random-state': self.random.getstate(),
      }
    return state

  def set_state(self, state):
    self.mutator.set_state(state['mutator-state'])
    self.random.setstate(state['random-state'])

  def runs(self, atheris_state):
    if atheris_state: # resume
      self.set_state(atheris_state)

    ctx = multiprocessing.get_context('spawn')
    p = ctx.Process(target=atheris_target,
                    args=(self.config,
                          self.SUT,
                          self.mutator,
                          log_server.queue),
                    name='Atheris')
    p.start()
    p.join()

    return None # We will not resume Atheris later
  
