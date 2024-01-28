import time
import os
import jsonpickle
from pathlib import Path

import scenic
scenic.setDebuggingOptions(verbosity=1, fullBacktrace=True)

from scenariogen.core.fuzzing.runner import Runner


class SeedTester:
  def __init__(self, config):
    self.config = config
    self.seed_paths = sorted(Path(config['seeds-folder']).glob('*'), key=lambda x: os.path.getmtime(x))
    self.seed_index = 0

  def set_state(self, state):
    pass

  def get_state(self):
    return None

  def input_eval(self, seed):
    try:
      sim_result = Runner.run({**self.config['SUT-config'],
                               **self.config['coverage-config'],
                               **seed.config,
                               'fuzz-input': seed,
                              })
    except Exception as e:
      print(f'Exception of type {type(e)} in SeedTester: {e}')
    else:
      if not sim_result is None and not sim_result.records['events'] is None:
        return sim_result.records['events']

    return None

  def run(self):
    seed_path = self.seed_paths[self.seed_index]
    with open(seed_path, 'r') as f:
      seed = jsonpickle.decode(f.read())
    self.seed_index += 1

    events = self.input_eval(seed)
    if events:
      with open(Path(self.config['events-folder'])/seed_path.name, 'w') as f:
        f.write(jsonpickle.encode(events, indent=1))

  def runs(self, generator_state):
    start_time = time.time()

    if generator_state: # resume
      self.set_state(generator_state)
      
    while time.time()-start_time < self.config['max-total-time'] and self.seed_index < len(self.seed_paths):
        self.run()
    
    return self.get_state()
