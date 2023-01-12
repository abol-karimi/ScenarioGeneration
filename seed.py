from dataclasses import dataclass
from typing import List
from collections import namedtuple

# This project
from signals import SignalType


ControlPoint = namedtuple('ControlPoint', ['t', 'd'])

@dataclass
class ParameterizedCurve:
  control_points : List[ControlPoint] = None

@dataclass
class Route:
  lanes : List[str] = None

@dataclass
class Seed:
  routes: List[Route] = None
  curves: List[ParameterizedCurve] = None
  signals: List[SignalType] = None



