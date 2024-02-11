import time


class Fuzzer:
  def __init__(self, config):
    self.config = config

  def get_state(self):
    pass

  def set_state(self):
    pass

  def gen_input(self):
    pass

  def run(self):
    fuzz_input = self.gen_input()

  def runs(self, fuzzer_state=None):
    start_time = time.time()

    if fuzzer_state:
      self.set_state(fuzzer_state)

    while time.time()-start_time < self.config['max-total-time']:
      self.run()
    
    return self.get_state()
