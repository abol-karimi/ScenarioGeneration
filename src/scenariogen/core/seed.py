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
  
def is_valid_trajectory(traj):
  # Spline degree range
  if traj.degree < 2 or traj.degree > 4:
    return False
  # ctrlpts type (tuple of triples)
  if not isinstance(traj.ctrlpts, tuple):
    return False
  for c in traj.ctrlpts:
    if not (isinstance(c, tuple) and len(c) == 3):
      return False
  # knotvector type
  if not isinstance(traj.knotvector, tuple):
    return False
  # knots are nondecreasing
  for i in range(len(traj.knotvector)-1):
    if traj.knotvector[i+1] < traj.knotvector[i]:
      return False

  # relation between the number of knots and control points
  if len(traj.knotvector) != traj.degree + len(traj.ctrlpts) + 1:
    return False
  
  return True
  

def is_valid_seed(seed):
  """Check some necessary (but not sufficient) conditions.
  """
  if not isinstance(seed, Seed):
    return False
  if not isinstance(seed.config, dict):
    return False
  if not isinstance(seed.routes, tuple):
    return False
  if not isinstance(seed.trajectories, tuple):
    return False
  if not isinstance(seed.signals, tuple):
    return False
  if not isinstance(seed.lengths, tuple):
    return False
  if not isinstance(seed.widths, tuple):
    return False
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
  for traj in seed.trajectories:
    if not is_valid_trajectory(traj):
      return False

  return True
