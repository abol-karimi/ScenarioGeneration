from random import Random
from collections import Counter



class FuzzCandidate:
  """Represent an input with additional attributes"""

  def __init__(self, fuzz_input):
    self.fuzz_input = fuzz_input

    # These will be needed for power schedules
    self.coverage = None
    self.distance = -1
    self.energy = 0.0
  

class PowerSchedule:
  def __init__(self, randomizer_seed):
    self.random = Random(randomizer_seed)
    self.coverage_frequency = Counter()

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
    self.assignEnergy(population)
    norm_energy = self.normalizedEnergy(population)
    fuzz_candidate = self.random.choices(population, weights=norm_energy)[0]
    return fuzz_candidate


class AFLFastSchedule(PowerSchedule):
  def __init__(self, randomizer_seed, exponent):
    super().__init__(randomizer_seed)
    self.exponent = exponent

  def assignEnergy(self, population):
    """Assigns each fuzz_candidate the same energy"""
    for fuzz_candidate in population:
      fuzz_candidate.energy = 1 / (self.coverage_frequency[fuzz_candidate.coverage] ** self.exponent)

 

