from dataclasses import dataclass
from typing import List, Tuple, Dict

# This project
from scenariogen.core.signals import SignalType
from scenariogen.core.errors import InvalidSeedError


@dataclass
class Spline:
  degree : int = None
  ctrlpts : Tuple[Tuple[float]] = None
  knotvector : Tuple[float] = None

@dataclass
class Seed:
  config: Dict = None
  routes: Tuple[str] = None
  footprints: Tuple[Spline] = None # maps the timing output (below) to the location of the car
  timings: Tuple[Spline] = None # maps time to the parameter value of the footprint spline
  signals: Tuple[SignalType] = None
  lengths: Tuple[float] = None
  widths: Tuple[float] = None
  
def validate_spline(spline):
  # Spline degree range
  if spline.degree < 2 or spline.degree > 4:
    raise InvalidSeedError('Invalid seed: spline.degree not in {2, 3, 4}')
  # ctrlpts type (tuple of triples)
  if not isinstance(spline.ctrlpts, tuple):
    raise InvalidSeedError('Invalid seed: ctrlpts is not a tuple')
  for c in spline.ctrlpts:
    if not isinstance(c, tuple):
      print(c)
      raise InvalidSeedError('Invalid seed: ctrlpt is not a tuple')
    if len(c) != 2:
      print(c)
      raise InvalidSeedError('Invalid seed: ctrlpt is not a pair')
  # knotvector type
  if not isinstance(spline.knotvector, tuple):
    raise InvalidSeedError('Invalid seed: knotvector is not a tuple')
  # knots are nondecreasing
  for i in range(len(spline.knotvector)-1):
    if spline.knotvector[i+1] < spline.knotvector[i]:
      raise InvalidSeedError('Invalid seed: knotvector is not nondecreasing')

  # relation between the number of knots and control points
  if len(spline.knotvector) != spline.degree + len(spline.ctrlpts) + 1:
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

  if not isinstance(seed.footprints, tuple):
    raise InvalidSeedError('Invalid seed: seed.footprints not an instance of tuple')

  if not isinstance(seed.timings, tuple):
    raise InvalidSeedError('Invalid seed: seed.timings not an instance of tuple')

  if not isinstance(seed.signals, tuple):
    raise InvalidSeedError('Invalid seed: seed.signals not an instance of tuple')

  if not isinstance(seed.lengths, tuple):
    raise InvalidSeedError('Invalid seed: seed.lengths not an instance of tuple')

  if not isinstance(seed.widths, tuple):
    raise InvalidSeedError('Invalid seed: seed.widths not an instance of tuple')

  n = len(seed.routes)
  if n == 0:
    raise InvalidSeedError('Invalid seed: len(seed.routes) = 0')

  if n != len(seed.footprints):
    raise InvalidSeedError('Invalid seed: len(footprints) != len(routes)')

  if n != len(seed.timings):
    raise InvalidSeedError('Invalid seed: len(timings) != len(routes)')
  
  if n != len(seed.signals):
    raise InvalidSeedError('Invalid seed: len(signals) != len(routes)')

  if n != len(seed.lengths):
    raise InvalidSeedError('Invalid seed: len(lengths) != len(routes)')

  if n != len(seed.widths):
    raise InvalidSeedError('Invalid seed: len(widths) != len(routes)')

  for spline in seed.footprints + seed.timings:
    validate_spline(spline)

