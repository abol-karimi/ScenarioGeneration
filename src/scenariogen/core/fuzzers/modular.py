from dataclasses import dataclass
from typing import Dict, Any, Set
import time

# This project
import scenariogen.core.fuzz_input as seed
from src.scenariogen.core.scenario import Scenario

@dataclass
class ModularFuzzer:
  config : Dict
  coverage : Any # For both evaluation and seed generation purposes
  mutator : Any
  scheduler : Any
  corpus : Any

  def run(self):
    start_time = time.time()

    # Add the initial seeds
    for seed in self.corpus.seeds:
      try:
        sim_result = Scenario({'fuzz_input': seed, **self.config}).run()
      except Exception as err: # TODO specify the exception (collision between the ego and a nonego)
        # assumes that the initial seeds are valid
        pass
      coverage = self.coverage.from_sim(sim_result)
      self.scheduler.add(seed, coverage)

    # Fuzzing loop
    for i in range(self.config['iterations']):
      print(f'Total elapsed time: {round(time.time()-start_time, 3)} seconds.')
      print('-'*20 + f'Starting iteration {i+1}/{self.config["iterations"]}' + '-'*20)
      seed = self.mutator.mutate(self.scheduler.choose())
      try:
        sim_result = Scenario(self.config, seed).run()
      except Exception as err: # TODO specify the exception (non-ego non-ego collision)
        print('\tInvalid mutant, discarding it:')
        print(f'\t{err}')
      # TODO except EgoCollision:
      #   classify: ego's fault, or non-ego's fault
      #   add seed to corpus if ego's fault
        continue
      coverage = self.coverage.from_sim(sim_result)
      self.scheduler.add(seed, coverage)
      if coverage.is_novel_to(self.coverage):
        self.corpus.add(seed)
        self.coverage += coverage

    return self.corpus
  
  def save(self, out_corpus):
    self.corpus.save(out_corpus)



