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
    self.SUT_config = config['SUT_config']
    self.coverage_config = config['coverage_config']
    self.coverages_statements = StatementCoverage([])
    self.coverages_predicateSet = PredicateSetCoverage([])
    self.coverages_predicates = PredicateCoverage([])
    self.mutator = config['mutator']
    self.crossOver = config['crossOver']
    self.schedule = config['schedule']
    
    self.seeds = []
    for seed_path in Path(config['seeds_folder']).glob('*'):
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
      sim_result = Scenario(fuzz_input).run({**self.SUT_config,
                                            **self.coverage_config})
      coverage = sim_result.records['coverage']
    except SimulationCreationError as e:
      print(e)
      coverage = None
    
    return coverage
    
  def run(self, fuzzer_state=None):
    start_time = time.time()

    if fuzzer_state:
      self.set_state(fuzzer_state)
    else:
      self.reset()

    while time.time()-start_time < self.config['max_total_time']:
      print(f'Total elapsed time: {round(time.time()-start_time, 3)} seconds.')
      fuzz_input = self.fuzz()
      coverage_statements = self.input_eval(fuzz_input)
      if coverage_statements is None:
        print('Simulation finished successfully, but no coverage recorded!')
      else:
        coverage_predicateSet = coverage_statements.cast_to(PredicateSetCoverage)
        coverage_predicates = coverage_statements.cast_to(PredicateCoverage)
        if len(coverage_statements - self.coverages_statements) > 0 \
            or len(coverage_predicates - self.coverages_predicates) > 0 \
            or len(coverage_predicateSet - self.coverages_predicateSet) > 0:

          candidate = FuzzCandidate(fuzz_input)
          candidate.coverage = coverage_statements
          self.population.append(candidate)
          self.coverages_statements.update(coverage_statements)
          self.coverages_predicateSet.update(coverage_predicateSet)
          self.coverages_predicates.update(coverage_predicates)
          
          # Save results to disk
          sha1 = hashlib.sha1(pickle.dumps(fuzz_input)).hexdigest()
          with open(Path(self.config['output_folder'])/f'fuzz-inputs/{sha1}.json', 'w') as f:
            f.write(jsonpickle.encode(fuzz_input))
          with open(Path(self.config['output_folder'])/f'coverages/{sha1}.json', 'w') as f:
            f.write(jsonpickle.encode(coverage_statements))
    
    # TODO return fuzzer state
    return None




