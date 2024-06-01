from random import Random
from collections import Counter
import logging


class PowerSchedule:
    def __init__(self, randomizer_seed):
        self.random = Random(randomizer_seed)
        self.feature_frequency = Counter()

    def get_state(self):
        return self.random.getstate()
    
    def set_state(self, state):
        self.random.setstate(state)

    def assignEnergy(self, population):
        """Assigns each fuzz_candidate the same energy"""
        for fuzz_candidate in population:
            fuzz_candidate.energy = 1

    def normalizedEnergy(self, population):
        """Normalize energy"""
        energy = list(map(lambda fuzz_candidate: fuzz_candidate.energy, population))
        sum_energy = sum(energy)  # Add up all values in energy
        assert sum_energy != 0
        norm_energy = list(map(lambda nrg: nrg / sum_energy, energy))
        return norm_energy

    def choose(self, population):
        """Choose weighted by normalized energy."""
        logger = logging.getLogger(__name__)
        self.assignEnergy(population)
        norm_energy = self.normalizedEnergy(population)
        fuzz_candidate = self.random.choices(population, weights=norm_energy)[0]
        logger.debug(f'Chose fuzz-candidate with fuzz-input-hash {fuzz_candidate.fuzz_input.hexdigest}')
        return fuzz_candidate





