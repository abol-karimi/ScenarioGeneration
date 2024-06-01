from .power import PowerSchedule


class AFLFastSchedule(PowerSchedule):
    def __init__(self, randomizer_seed, exponent):
        super().__init__(randomizer_seed)
        self.exponent = exponent

    def assignEnergy(self, population):
        for fuzz_candidate in population:
            fuzz_candidate.energy = 1 / (self.feature_frequency[fuzz_candidate.coverage] ** self.exponent)