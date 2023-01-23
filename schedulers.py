from typing import Set, Sequence, List
from queue import Queue
import random

# This project
from seed import Seed

class FIFOScheduler:
  seeds = None # Queue

  def choose(self):
    return self.seeds.get()
  
  def add(self, seed):
    self.seeds.put(seed)


class RandomScheduler:
  seeds : List[Seed] = []

  def choose(self):
    return random.choice(self.seeds)
  
  def add(self, seed, events):
    self.seeds.append(seed)