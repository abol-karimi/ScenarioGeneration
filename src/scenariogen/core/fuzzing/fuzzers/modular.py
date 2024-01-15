import time
from pathlib import Path
import jsonpickle
import pickle
import hashlib

from scenic.core.simulators import SimulationCreationError

# This project
from scenariogen.core.scenario import Scenario
from scenariogen.core.fuzzing.schedules import FuzzCandidate
from scenariogen.core.coverages.coverage import StatementCoverage, PredicateSetCoverage, PredicateCoverage

class ModularFuzzer:
  def __init__(self, config):
    self.config = config
    self.coverage_statements_seen = StatementCoverage([])
    self.coverage_predicateSets_seen = PredicateSetCoverage([])
    self.coverage_predicates_seen = PredicateCoverage([])
    self.mutator = config['mutator']
    self.crossOver = config['crossOver']
    self.schedule = config['schedule']
    
    self.seeds = []
    for seed_path in Path(config['seeds-folder']).glob('*'):
      with open(seed_path, 'r') as f:
        seed = jsonpickle.decode(f.read())
      self.seeds.append(seed)
    
    self.inputs = [] # The inputs (seeds or their fuzz) that are evaluated

  def reset(self):
    self.population = list(map(lambda x: FuzzCandidate(x), self.seeds))
    self.seed_index = 0

  def fuzz(self):
    """Returns first each seed once and then generates new inputs"""
    if self.seed_index < len(self.seeds):
        # Still seeding
        fuzz_input = self.seeds[self.seed_index]
        self.seed_index += 1
    else:
        # Mutating
        candidate = self.schedule.choose(self.population)
        fuzz_input = self.mutator.mutate(candidate.fuzz_input)

    self.inputs.append(fuzz_input)
    return fuzz_input
  
  def input_eval(self, fuzz_input):
    try:
      sim_result = Scenario(fuzz_input).run({**self.config['SUT-config'],
                                            **self.config['coverage-config']})
      events = sim_result.records['events']
      coverage = sim_result.records['coverage']
    except SimulationCreationError as e:
      print(e)
      events = None
      coverage = None
    
    return events, coverage
    
  def run(self, fuzzer_state=None):
    start_time = time.time()

    if fuzzer_state:
      self.set_state(fuzzer_state)
    else:
      self.reset()

    while time.time()-start_time < self.config['max-total-time']:
      print(f'Total elapsed time: {round(time.time()-start_time, 3)} seconds.')
      fuzz_input = self.fuzz()
      coverage_events, coverage_statements = self.input_eval(fuzz_input)
      if coverage_events is None:
        print('Simulation finished successfully, but events not recorded!')
      elif coverage_statements is None:
        print('Events recorded, but coverage not recorded! Saving the fuzz-input in bugs...')
        fuzz_input_bytes = jsonpickle.encode(fuzz_input, indent=1).encode('utf-8')
        fuzz_input_hash = hashlib.sha1(fuzz_input_bytes).hexdigest()
        with open(Path(self.config['bugs-folder'])/fuzz_input_hash, 'wb') as f:
          f.write(fuzz_input_bytes)        
      else:
        coverage_predicateSet = coverage_statements.cast_to(PredicateSetCoverage)
        coverage_predicates = coverage_statements.cast_to(PredicateCoverage)
        if len(coverage_statements - self.coverage_statements_seen) > 0 \
            or len(coverage_predicates - self.coverage_predicates_seen) > 0 \
            or len(coverage_predicateSet - self.coverage_predicateSets_seen) > 0:

          candidate = FuzzCandidate(fuzz_input)
          candidate.coverage = coverage_statements
          self.population.append(candidate)
          self.coverage_statements_seen.update(coverage_statements)
          self.coverage_predicateSets_seen.update(coverage_predicateSet)
          self.coverage_predicates_seen.update(coverage_predicates)
          
          # Save fuzz-input and its coverage events to disk
          fuzz_input_bytes = jsonpickle.encode(fuzz_input, indent=1).encode('utf-8')
          fuzz_input_hash = hashlib.sha1(fuzz_input_bytes).hexdigest()
          with open(Path(self.config['fuzz-inputs-folder'])/fuzz_input_hash, 'wb') as f:
            f.write(fuzz_input_bytes)
          with open(Path(self.config['events-folder'])/fuzz_input_hash, 'w') as f:
            f.write(jsonpickle.encode(coverage_events, indent=1))
    
    # TODO return fuzzer state
    return None




