import time
from pathlib import Path
import jsonpickle
import hashlib
from collections import Counter

from scenic.core.simulators import SimulationCreationError

# This project
from scenariogen.core.scenario import Scenario
from scenariogen.core.fuzzing.schedules import FuzzCandidate
from scenariogen.core.coverages.coverage import StatementSetCoverage, PredicateSetCoverage, PredicateCoverage, StatementCoverage
from scenariogen.core.errors import InvalidFuzzInputError, CoverageError

class ModularFuzzer:
  def __init__(self, config):
    self.config = config
    self.coverage_seen = StatementSetCoverage([])
    self.mutator = config['mutator']
    self.crossOver = config['crossOver']
    self.schedule = config['schedule']
    
    self.seeds = []
    for seed_path in Path(config['seeds-folder']).glob('*'):
      with open(seed_path, 'r') as f:
        seed = jsonpickle.decode(f.read())
      self.seeds.append(seed)
    
    self.reset()
    
  def get_state(self):
    state = {
      'coverage_seen': self.coverage_seen,
      'mutator_state': self.mutator.get_state(),
      'crossOver_state': self.crossOver.get_state(),
      'schedule_state': self.schedule.get_state(),
      'fuzz_candidates': self.fuzz_candidates,
      'seed_index': self.seed_index,
      }
    return state

  def set_state(self, state):
    self.coverage_seen = state['coverage_seen']
    self.mutator.set_state(state['mutator_state'])
    self.crossOver.set_state(state['crossOver_state'])
    self.schedule.set_state(state['schedule_state'])
    self.fuzz_candidates = state['fuzz_candidates']
    self.seed_index = state['seed_index']

  def reset(self):
    self.fuzz_candidates = []
    self.seed_index = 0

  def fuzz(self):
    """Returns first each seed once and then generates new inputs"""
    if self.seed_index < len(self.seeds):
      # Still seeding
      fuzz_input = self.seeds[self.seed_index]
      self.seed_index += 1
    else:
      # Mutating
      candidate = self.schedule.choose(self.fuzz_candidates)
      fuzz_input = self.mutator.mutate(candidate.fuzz_input)

    return fuzz_input
  
  def input_eval(self, fuzz_input):
    try:
      sim_result = Scenario(fuzz_input).run({**self.config['SUT-config'],
                                            **self.config['coverage-config']})
    except SimulationCreationError as e:
      raise InvalidFuzzInputError(e)

    events = sim_result.records['events']
    statement_coverage = sim_result.records['coverage']
    if events is None:
      raise CoverageError('Simulation finished successfully, but no coverage recorded!')
    elif statement_coverage is None:
      raise CoverageError('Events recorded, but no coverage recorded!')
    else:
      return events, statement_coverage
    
  def run(self):
    fuzz_input = self.fuzz()
    fuzz_input_bytes = jsonpickle.encode(fuzz_input, indent=1).encode('utf-8')
    fuzz_input_hash = hashlib.sha1(fuzz_input_bytes).hexdigest()

    try:
      coverage_events, statement_coverage = None, None
      coverage_events, statement_coverage = self.input_eval(fuzz_input)

    except InvalidFuzzInputError as e:
      print(e)
    except Exception as e:
      print(f'{e} Saving the fuzz-input with hash {fuzz_input_hash} in bugs...')
      with open(Path(self.config['bugs-folder'])/fuzz_input_hash, 'wb') as f:
        f.write(fuzz_input_bytes)
    else:
      if statement_coverage in self.coverage_seen:
        coverage_events, statement_coverage = None, None
      else:
        candidate = FuzzCandidate(fuzz_input, fuzz_input_hash)
        self.fuzz_candidates.append(candidate)
        self.coverage_seen = self.coverage_seen + StatementSetCoverage([statement_coverage])
        
        # Save fuzz-input and its statement-coverage events to disk
        with open(Path(self.config['fuzz-inputs-folder'])/fuzz_input_hash, 'wb') as f:
          f.write(fuzz_input_bytes)
        with open(Path(self.config['events-folder'])/fuzz_input_hash, 'w') as f:
          f.write(jsonpickle.encode(coverage_events, indent=1))
        
    finally:
      return coverage_events, statement_coverage
  
  def runs(self, fuzzer_state=None):
    start_time = time.time()

    if fuzzer_state:
      self.set_state(fuzzer_state)
    else:
      self.reset()

    while time.time()-start_time < self.config['max-total-time']:
      self.run()
    
    return self.get_state()
  

class CountingFuzzer(ModularFuzzer):
  """Count how often each coverage is exercised."""
  def get_state(self):
    return {**super().get_state(),
            'coverage_frequency': self.schedule.coverage_frequency}

  def set_state(self, state):
    super().set_state(state)
    self.schedule.coverage_frequency = state['coverage_frequency']

  def reset(self):
    """Reset coverage frequency"""
    super().reset()
    self.schedule.coverage_frequency = Counter()


class CountingPredicateSetFuzzer(CountingFuzzer):
  """Count how often predicate-sets are exercised."""

  def run(self):
    """Inform scheduler about coverage frequency"""
    events, statement_coverage = super().run()

    if statement_coverage:
      coverage_predicates = statement_coverage.cast_to(PredicateCoverage)
      self.fuzz_candidates[-1].coverage = coverage_predicates
      self.schedule.coverage_frequency[coverage_predicates] += 1

    return events, statement_coverage


class CountingStatementSetFuzzer(CountingFuzzer):
  """Count how often statement-sets are exercised."""

  def run(self):
    """Inform scheduler about coverage frequency"""
    events, statement_coverage = super().run()

    if statement_coverage:
      self.fuzz_candidates[-1].coverage = statement_coverage
      self.schedule.coverage_frequency[statement_coverage] += 1

    return events, statement_coverage
