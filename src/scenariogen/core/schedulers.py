from typing import Set, Sequence, List, Dict, Any
from dataclasses import dataclass
from queue import Queue, PriorityQueue

import random

# This project
from src.scenariogen.core.seed_corpus import Seed

class FIFOScheduler:
  seeds = Queue() # Queue

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


@dataclass
class PriorityScheduler:
  config : Dict[str, Any]
  coverage = {} # How many times each predicate is covered
  seeds = PriorityQueue()

  def choose(self):
    score, insertion_order, seed = self.seeds.queue[0]
    return seed

  def add(self, seed, coverage):
    score = self.priority_score(seed, coverage)
    self.seeds.put((score, self.seeds.qsize(), seed))
    
    # Update the coverage
    for p in coverage:
      if p in self.coverage:
        self.coverage[p] += 1
      else:
        self.coverage[p] = 1
  
  def priority_score(self, seed, predicates):
    return len(predicates) # simplest priority score

