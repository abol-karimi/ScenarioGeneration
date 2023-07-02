from dataclasses import dataclass
from typing import List, Tuple, Dict

# This project
from scenariogen.core.signals import SignalType
from scenariogen.core.errors import InvalidSeedError


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
  
def validate_trajectory(traj):
  # Spline degree range
  if traj.degree < 2 or traj.degree > 4:
    raise InvalidSeedError('Invalid seed: traj.degree not in {2, 3, 4}')
  # ctrlpts type (tuple of triples)
  if not isinstance(traj.ctrlpts, tuple):
    raise InvalidSeedError('Invalid seed: ctrlpts is not a tuple')
  for c in traj.ctrlpts:
    if not (isinstance(c, tuple) and len(c) == 3):
      raise InvalidSeedError('Invalid seed: ctrlpt is not a triple')
  # knotvector type
  if not isinstance(traj.knotvector, tuple):
    raise InvalidSeedError('Invalid seed: knotvector is not a tuple')
  # knots are nondecreasing
  for i in range(len(traj.knotvector)-1):
    if traj.knotvector[i+1] < traj.knotvector[i]:
      raise InvalidSeedError('Invalid seed: knotvector is not nondecreasing')

  # relation between the number of knots and control points
  if len(traj.knotvector) != traj.degree + len(traj.ctrlpts) + 1:
    raise InvalidSeedError('Invalid seed: len(knotvector) != degree + len(ctrlpts) + 1')
  

def validate_seed(seed):
  """Check some necessary (but not sufficient) conditions.
  """
  if not isinstance(seed, Seed):
    raise InvalidSeedError('Invalid seed: not an instance of Seed')

  if not isinstance(seed.config, dict):
    raise InvalidSeedError('Invalid seed: seed.config not an instance of dict')

  if not isinstance(seed.routes, tuple):
    raise InvalidSeedError('Invalid seed: seed.routes not an instance of tuple')

  if not isinstance(seed.trajectories, tuple):
    raise InvalidSeedError('Invalid seed: seed.trajectories not an instance of tuple')

  if not isinstance(seed.signals, tuple):
    raise InvalidSeedError('Invalid seed: seed.signals not an instance of tuple')

  if not isinstance(seed.lengths, tuple):
    raise InvalidSeedError('Invalid seed: seed.lengths not an instance of tuple')

  if not isinstance(seed.widths, tuple):
    raise InvalidSeedError('Invalid seed: seed.widths not an instance of tuple')

  n = len(seed.routes)
  if n == 0:
    raise InvalidSeedError('Invalid seed: len(seed.routes) = 0')

  if n != len(seed.trajectories):
    raise InvalidSeedError('Invalid seed: len(trajectories) != len(routes)')

  if n != len(seed.signals):
    raise InvalidSeedError('Invalid seed: len(signals) != len(routes)')

  if n != len(seed.lengths):
    raise InvalidSeedError('Invalid seed: len(lengths) != len(routes)')

  if n != len(seed.widths):
    raise InvalidSeedError('Invalid seed: len(widths) != len(routes)')

  for traj in seed.trajectories:
    validate_trajectory(traj)

