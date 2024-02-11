from collections import Counter


# This project
from scenariogen.core.fuzzing.fuzzers.greybox import GreyboxFuzzer
from scenariogen.core.coverages.coverage import PredicateCoverage


class CountingFuzzer(GreyboxFuzzer):
  """Count how often each coverage is exercised."""
  def __init__(self, config):
    super().__init__(config)
    self.schedule.coverage_frequency = Counter()

  def get_state(self):
    return {**super().get_state(),
            'coverage_frequency': self.schedule.coverage_frequency}

  def set_state(self, state):
    super().set_state(state)
    self.schedule.coverage_frequency = state['coverage_frequency']  


class CountingPredicateSetFuzzer(CountingFuzzer):
  """Count how often predicate-sets are exercised."""

  def run(self):
    """Inform scheduler about coverage frequency"""
    statement_coverage = super().run()

    if not statement_coverage is None:
      coverage_predicates = statement_coverage.cast_to(PredicateCoverage)
      self.fuzz_candidates[-1].coverage = coverage_predicates
      self.schedule.coverage_frequency[coverage_predicates] += 1

    return statement_coverage


class CountingStatementSetFuzzer(CountingFuzzer):
  """Count how often statement-sets are exercised."""

  def run(self):
    """Inform scheduler about coverage frequency"""
    statement_coverage = super().run()

    if statement_coverage:
      self.fuzz_candidates[-1].coverage = statement_coverage
      self.schedule.coverage_frequency[statement_coverage] += 1

    return statement_coverage
