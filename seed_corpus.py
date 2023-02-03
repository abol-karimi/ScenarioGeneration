from dataclasses import dataclass
from typing import List
from collections import namedtuple
from geomdl import BSpline

# This project
from signals import SignalType


@dataclass
class Route:
  lanes : List[str] = None

@dataclass
class Seed:
  routes: List[Route] = None
  curves: List = None
  signals: List[SignalType] = None
  
  def is_valid(self):
    """Check some necessary (but not sufficient) conditions.
    """
    if len(self.routes) != len(self.curves):
      return False
    if len(self.routes) != len(self.signals):
      return False
    if len(self.routes) == 0:
      return False
      
    return True

@dataclass
class SeedCorpus:
  seeds : List[Seed] = None

  def load(self, filename):
    pass

  def add(self, seed):
    self.seeds.append(seed)

  def save(self, filename):
    pass

