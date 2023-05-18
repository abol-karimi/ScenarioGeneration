from dataclasses import dataclass, field
from typing import List, Optional
from collections import namedtuple
from geomdl import BSpline
import jsonpickle

# This project
from signals import SignalType


@dataclass
class Route:
  lanes : List[str] = None

@dataclass
class Seed:
  routes: List[Route] = None
  trajectories: List = None
  signals: List[SignalType] = None
  
  def is_valid(self):
    """Check some necessary (but not sufficient) conditions.
    """
    if len(self.routes) != len(self.trajectories):
      return False
    if len(self.routes) != len(self.signals):
      return False
    if len(self.routes) == 0:
      return False
      
    return True


@dataclass
class SeedCorpus:
  seeds : List[Seed] = field(default_factory=list)

  def save(self, filename):
    """"Save the corpus to a json file."""
    seeds_data = []
    for seed in self.seeds:
      routes = seed.routes
      curves_data = [{'degree':c.degree,
                      'ctrlpts': c.ctrlpts,
                      'knotvector':[float(r) for r in c.knotvector]}
                  for c in seed.trajectories]
      signals = [s.name for s in seed.signals]
      seed_data = {'routes':routes, 'curves_data':curves_data, 'signals':signals}
      seeds_data.append(seed_data)

    with open(filename, 'w') as f:
      seeds_json = jsonpickle.encode(seeds_data)
      f.write(seeds_json)

  def load(self, filename):
    """"Load the corpus from a json file."""
    with open(filename, 'r') as f:
      seeds_data = jsonpickle.decode(f.read())

    for seed_data in seeds_data:
      curves = []
      for curve_data in seed_data['curves_data']:
        curve = BSpline.Curve(normalize_kv=False)
        curve.degree = curve_data['degree']
        curve.ctrlpts = curve_data['ctrlpts']
        curve.knotvector = curve_data['knotvector']
        curves.append(curve)
      seed = Seed(routes=seed_data['routes'],
                  trajectories=curves,
                  signals=[SignalType[s] for s in seed_data['signals']])
      self.seeds.append(seed)


  def add(self, seed):
    self.seeds.append(seed)



