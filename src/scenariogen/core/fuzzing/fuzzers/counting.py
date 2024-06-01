from collections import Counter
import logging

from scenariogen.core.fuzzing.fuzzers.mutation import MutationFuzzer
from scenariogen.core.coverages.coverage import PredicateCoverage


class CountingPredicateSetFuzzer(MutationFuzzer):
    """Count how often predicate-sets are exercised."""
    def __init__(self, config):
        super().__init__(config)
        self.schedule.feature_frequency = Counter()

    def get_state(self):
        return {**super().get_state(),
                'feature_frequency': self.schedule.feature_frequency}

    def set_state(self, state):
        super().set_state(state)
        self.schedule.feature_frequency = state['feature_frequency']

    def run(self):
        """Inform scheduler about coverage frequency"""
        fuzz_candidate, statement_coverage = super().run()

        logger = logging.getLogger(__name__)
        if not fuzz_candidate is None:
            predicateCoverage = statement_coverage.cast_to(PredicateCoverage)
            fuzz_candidate.coverage = predicateCoverage
            self.schedule.feature_frequency[predicateCoverage] += 1
            logger.debug(f"Inform the scheduler about the coverage frequency.")

        return fuzz_candidate, statement_coverage
