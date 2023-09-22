from dataclasses import dataclass
from typing import List, Tuple, Dict

# This project
from scenariogen.core.signals import SignalType
from scenariogen.core.errors import InvalidFuzzInputError


@dataclass
class Spline:
  degree : int = None
  ctrlpts : Tuple[Tuple[float]] = None
  knotvector : Tuple[float] = None

@dataclass
class FuzzInput:
  config: Dict = None
  blueprints: Tuple[str] = None
  routes: Tuple[str] = None
  footprints: Tuple[Spline] = None # maps the timing output (below) to the location of the car
  timings: Tuple[Spline] = None # maps time to the parameter value of the footprint spline
  signals: Tuple[SignalType] = None

  
def validate_spline(spline):
  # Spline degree range
  if spline.degree < 2 or spline.degree > 4:
    raise InvalidFuzzInputError('Invalid input: spline.degree not in {2, 3, 4}')
  # ctrlpts type (tuple of triples)
  if not isinstance(spline.ctrlpts, tuple):
    raise InvalidFuzzInputError('Invalid input: ctrlpts is not a tuple')
  for c in spline.ctrlpts:
    if not isinstance(c, tuple):
      print(c)
      raise InvalidFuzzInputError('Invalid input: ctrlpt is not a tuple')
    if len(c) != 2:
      print(c)
      raise InvalidFuzzInputError('Invalid input: ctrlpt is not a pair')
  # knotvector type
  if not isinstance(spline.knotvector, tuple):
    raise InvalidFuzzInputError('Invalid input: knotvector is not a tuple')
  # knots are nondecreasing
  for i in range(len(spline.knotvector)-1):
    if spline.knotvector[i+1] < spline.knotvector[i]:
      raise InvalidFuzzInputError('Invalid input: knotvector is not nondecreasing')

  # relation between the number of knots and control points
  if len(spline.knotvector) != spline.degree + len(spline.ctrlpts) + 1:
    raise InvalidFuzzInputError('Invalid input: len(knotvector) != degree + len(ctrlpts) + 1')
  

def validate_input(fuzz_input):
  """Check some necessary (but not sufficient) conditions.
  """
  if not isinstance(fuzz_input, FuzzInput):
    raise InvalidFuzzInputError('Invalid input: not an instance of FuzzInput')

  if not isinstance(fuzz_input.config, dict):
    raise InvalidFuzzInputError('Invalid input: fuzz_input.config not an instance of dict')

  if not isinstance(fuzz_input.routes, tuple):
    raise InvalidFuzzInputError('Invalid input: fuzz_input.routes not an instance of tuple')

  if not isinstance(fuzz_input.footprints, tuple):
    raise InvalidFuzzInputError('Invalid input: fuzz_input.footprints not an instance of tuple')

  if not isinstance(fuzz_input.timings, tuple):
    raise InvalidFuzzInputError('Invalid input: fuzz_input.timings not an instance of tuple')

  if not isinstance(fuzz_input.signals, tuple):
    raise InvalidFuzzInputError('Invalid input: fuzz_input.signals not an instance of tuple')

  n = len(fuzz_input.routes)
  if n == 0:
    raise InvalidFuzzInputError('Invalid input: len(fuzz_input.routes) = 0')

  if n != len(fuzz_input.footprints):
    raise InvalidFuzzInputError('Invalid input: len(footprints) != len(routes)')

  if n != len(fuzz_input.timings):
    raise InvalidFuzzInputError('Invalid input: len(timings) != len(routes)')
  
  if n != len(fuzz_input.signals):
    raise InvalidFuzzInputError('Invalid input: len(signals) != len(routes)')

  for spline in fuzz_input.footprints + fuzz_input.timings:
    validate_spline(spline)

