from dataclasses import dataclass
from typing import List, Tuple

# This project
from scenariogen.core.signals import SignalType


@dataclass
class Route:
  lanes : List[str] = None

@dataclass
class Trajectory:
  degree : int = None
  ctrlpts : List[Tuple[float]] = None
  knotvector : List[float] = None

@dataclass
class Seed:
  routes: List[Route] = None
  trajectories: List[Trajectory] = None
  signals: List[SignalType] = None
  lengths: List[float] = None
  widths: List[float] = None
  
def is_valid(seed):
  """Check some necessary (but not sufficient) conditions.
  """
  n = len(seed.routes)
  if n == 0:
    return False
  if n != len(seed.trajectories):
    return False
  if n != len(seed.signals):
    return False
  if n != len(seed.lengths):
    return False
  if n != len(seed.widths):
    return False

  return True
