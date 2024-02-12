from collections import Counter

from scenariogen.core.fuzzing.fuzzers.greybox import GreyboxFuzzer
from scenariogen.core.coverages.coverage import PredicateCoverage


class CountingPredicateSetFuzzer(GreyboxFuzzer):
  """Count how often predicate-sets are exercised."""
  def __init__(self, config):
    super().__init__(config)
    self.schedule.coverage_frequency = Counter()

  def get_state(self):
    return {**super().get_state(),
            'coverage_frequency': self.schedule.coverage_frequency}

  def set_state(self, state):
    super().set_state(state)
    self.schedule.coverage_frequency = state['coverage_frequency']

  def run(self):
    """Inform scheduler about coverage frequency"""
    fuzz_candidate, statement_coverage = super().run()

    if not fuzz_candidate is None:
      coverage_predicates = statement_coverage.cast_to(PredicateCoverage)
      fuzz_candidate.coverage = coverage_predicates
      self.schedule.coverage_frequency[coverage_predicates] += 1

    return statement_coverage
