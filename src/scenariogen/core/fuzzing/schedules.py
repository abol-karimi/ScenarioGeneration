from random import Random

# This project
from scenariogen.core.fuzz_input import FuzzInput
from scenariogen.core.coverages.coverage import StatementCoverage


class FuzzCandidate:
    """Represent an input with additional attributes"""

    def __init__(self, fuzz_input):
        self.fuzz_input = fuzz_input

        # These will be needed for advanced power schedules
        self.coverage = StatementCoverage([])
        self.distance = -1
        self.energy = 0.0


class PowerSchedule:
  def __init__(self, randomizer_seed=0):
    self.random = Random(randomizer_seed)

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
    self.assignEnergy(population)
    norm_energy = self.normalizedEnergy(population)
    fuzz_candidate = self.random.choices(population, weights=norm_energy)[0]
    return fuzz_candidate
 

