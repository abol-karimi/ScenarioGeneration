from pathlib import Path
import jsonpickle
from random import Random

# This project
from scenariogen.core.fuzzing.runner import SUTRunner
from scenariogen.core.fuzzing.schedules import FuzzCandidate
from scenariogen.core.coverages.coverage import StatementSetCoverage

from .base import Fuzzer
 

class GreyboxFuzzer(Fuzzer):
  def __init__(self, config):
    self.config = config
    self.coverage_seen = StatementSetCoverage([])
    self.random = Random(config['randomizer-seed'])
    self.mutator = config['mutator-config']['mutator']
    self.schedule = config['schedule']
    
    self.seeds = []
    for seed_path in Path(config['seeds-folder']).glob('*'):
      with open(seed_path, 'r') as f:
        seed = jsonpickle.decode(f.read())
      self.seeds.append(seed)
    
    self.fuzz_candidates = []
    self.seed_index = 0
    
  def get_state(self):
    state = {
      'coverage-seen': self.coverage_seen,
      'random-state': self.random.getstate(),
      'mutator-state': self.mutator.get_state(),
      'schedule-state': self.schedule.get_state(),
      'fuzz-candidates': self.fuzz_candidates,
      'seed-index': self.seed_index,
      }
    return state

  def set_state(self, state):
    self.coverage_seen = state['coverage-seen']
    self.random.setstate(state['random-state'])
    self.mutator.set_state(state['mutator-state'])
    self.schedule.set_state(state['schedule-state'])
    self.fuzz_candidates = state['fuzz-candidates']
    self.seed_index = state['seed-index']

  def input_eval(self, fuzz_input):
    sim_result = SUTRunner.run({**self.config['SUT-config'],
                                **self.config['coverage-config'],
                                **fuzz_input.config,
                                'fuzz-input': fuzz_input,
                                })
    if (not sim_result is None) and 'coverage' in sim_result.records:
      # For debugging purposes, save events
      with open(Path(self.config['events-folder'])/fuzz_input.hexdigest, 'w') as f:
        f.write(jsonpickle.encode(sim_result.records['events'], indent=1))

      return sim_result.records['coverage']
    else:
      return None

  def fuzz(self):
      """Generates a new input by fuzzing a candidate in the population"""
      selected = self.schedule.choose(self.fuzz_candidates)

      # Stacking: Apply multiple mutations to generate the candidate
      fuzz_input = selected.fuzz_input
      mutations_per_fuzz = self.random.randint(1, self.config['mutator-config']['max-mutations-per-fuzz'])
      for i in range(mutations_per_fuzz):
          fuzz_input = self.mutator.mutate(fuzz_input)
      return fuzz_input
  
  def gen_input(self):
    """First returns each seed once, then generates new inputs"""
    if self.seed_index < len(self.seeds):
      # Still seeding
      fuzz_input = self.seeds[self.seed_index]
      self.seed_index += 1
    else:
      # Fuzzing
      fuzz_input = self.fuzz()

    return fuzz_input
    
  def run(self):
    fuzz_input = self.gen_input()
    statement_coverage = self.input_eval(fuzz_input)
    if not statement_coverage is None:
      # Save the fuzz-input and its coverage to disk
      with open(Path(self.config['fuzz-inputs-folder'])/fuzz_input.hexdigest, 'wb') as f:
        f.write(fuzz_input.bytes)
      with open(Path(self.config['coverages-folder'])/fuzz_input.hexdigest, 'w') as f:
        f.write(jsonpickle.encode(statement_coverage, indent=1))

      if not statement_coverage in self.coverage_seen:
        self.fuzz_candidates.append(FuzzCandidate(fuzz_input))
        self.coverage_seen = self.coverage_seen + StatementSetCoverage([statement_coverage])    
        print(f'The fuzz input with hash {fuzz_input.hexdigest} expanded the coverage! Added to fuzz candidates.')

    return statement_coverage
