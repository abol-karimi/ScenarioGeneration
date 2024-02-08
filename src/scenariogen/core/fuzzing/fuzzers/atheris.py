import sys
import jsonpickle
from pathlib import Path
import shutil
from typing import Any
import multiprocessing
import hashlib
from random import Random
import atheris
import setproctitle


# This project
from scenariogen.core.fuzzing.runner import SUTRunner


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
    if sim_result and 'events' in sim_result.records:
      # Save coverage events to disk
      fuzz_input_hash = hashlib.sha1(input_bytes).hexdigest()
      with open(Path(self.config['events-folder'])/fuzz_input_hash, 'w') as f:
        f.write(jsonpickle.encode(sim_result.records['events'], indent=1))


#------------------------------------
#---------- Atheris wrapper ---------
#------------------------------------
def atheris_target(libfuzzer_config, SUT, mutator):
  setproctitle.setproctitle('Atheris target')
  atheris.instrument_all()
  atheris.Setup(sys.argv + libfuzzer_config,
                SUT,
                custom_mutator=mutator)
  atheris.Fuzz()


class AtherisFuzzer:
  def __init__(self, config):
    self.config = config
    self.random = Random(config['randomizer-seed'])
    self.mutator = MutatorCallback({**config['mutator-config'],
                                    'random': self.random})
    self.libfuzzer_config = [f"-max_total_time={config['max-total-time']}",
                             f"-artifact_prefix={Path(config['bugs-folder'])}/",
                             f"-max_len={config['max-seed-length']}",
                             f"-timeout=300", # scenarios taking more than 5 minutes are considered as bugs
                             f"-report_slow_units=120", # scenarios taking more than 2 minutes are considered slow
                             f"-rss_limit_mb=16384",
                             Path(config['fuzz-inputs-folder']).as_posix(),
                             config['seeds-folder'],
                            ]
    self.SUT = SUTCallback({**config['SUT-config'],
                            **config['coverage-config'],
                            'events-folder': config['events-folder'],
                            })

  def runs(self, atheris_state):
    if atheris_state: # resume
      self.set_state(atheris_state)

    ctx = multiprocessing.get_context('spawn')
    p = ctx.Process(target=atheris_target,
                    name='Atheris',
                    args=(self.libfuzzer_config,
                          self.SUT,
                          self.mutator))
    p.start()
    p.join()

    # include the seeds in the ouput
    fuzz_inputs_path = Path(self.config['fuzz-inputs-folder'])
    for seed_path in Path(self.config['seeds-folder']).glob('*'):
      shutil.copy(seed_path, fuzz_inputs_path)

    return None # We will not resume Atheris later
  
  def get_state(self):
    state = {
      'mutator-state': self.mutator.get_state(),
      'random_state': self.random.getstate(),
      }
    return state

  def set_state(self, state):
    self.mutator.set_state(state['mutator-state'])
    self.random.setstate(state['random_state'])