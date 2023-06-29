from dataclasses import dataclass
from typing import List, Tuple, Dict

# This project
from scenariogen.core.signals import SignalType


@dataclass
class Trajectory:
  degree : int = None
  ctrlpts : Tuple[Tuple[float]] = None
  knotvector : Tuple[float] = None

@dataclass
class Seed:
  config: Dict = None
  routes: Tuple[str] = None
  trajectories: Tuple[Trajectory] = None
  signals: Tuple[SignalType] = None
  lengths: Tuple[float] = None
  widths: Tuple[float] = None
  
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
