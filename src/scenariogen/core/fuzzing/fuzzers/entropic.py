import logging
from collections import Counter
import jsonpickle
from pathlib import Path

from scenariogen.core.fuzzing.fuzzers.mutation import MutationFuzzer


class FuzzCandidate:
    """Represent an input with additional attributes"""

    def __init__(self, fuzz_input):
        self.fuzz_input = fuzz_input
        
        #--- These will be needed for power schedules
        # For each feature, the number of times it was covered
        self.feature_frequency = Counter()

        # The calculated energy of the fuzz candidate
        self.energy = 0.0
        
        # If the global frequency of a locally covered feature is changed, the energy needs an update
        self.NeedsEnergyUpdate = False

        self.SumIncidence = 0.0
        self.NumExecutedMutations = 0


class EntropicFuzzer(MutationFuzzer):
    def __init__(self, config):
        super().__init__(config)
        self.schedule.reset_coverage_frequency()

    def instantiate_fuzz_candidate(self, fuzz_input, features):
        fuzz_candidate = FuzzCandidate(fuzz_input)
        fuzz_candidate.feature_frequency.update(features)
        return fuzz_candidate

    def run(self):
        new_fuzz_candidate, statement_coverage = super().run()

        if new_fuzz_candidate:
            self.schedule.DistributionNeedsUpdate = True

