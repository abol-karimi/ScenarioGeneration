from dataclasses import dataclass, field
from typing import List, Dict, Tuple
from geomdl import BSpline
import jsonpickle

# This project
from scenariogen.core.signals import SignalType


@dataclass
class Route:
  lanes : List[str] = None

@dataclass
class Seed:
  routes: List[Route] = None
  trajectories: List = None
  signals: List[SignalType] = None
  lengths: List[float] = None
  widths: List[float] = None
  
  def is_valid(self):
    """Check some necessary (but not sufficient) conditions.
    """
    n = len(self.routes)
    if n == 0:
      return False
    if n != len(self.trajectories):
      return False
    if n != len(self.signals):
      return False
    if n != len(self.lengths):
      return False
    if n != len(self.widths):
      return False

    return True


@dataclass
class SeedCorpus:
  seeds : List[Seed] = field(default_factory=list)
  config : Dict = field(default_factory=dict)

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
      seed_data = {'routes':routes, 
                   'curves_data':curves_data, 
                   'signals':signals,
                   'lengths': seed.lengths,
                   'widths': seed.widths}
      seeds_data.append(seed_data)
    
    corpus_data = {'seeds_data': seeds_data,
                   'config': self.config}

    with open(filename, 'w') as f:
      corpus_json = jsonpickle.encode(corpus_data)
      f.write(corpus_json)

  def load(self, filename):
    """"Load the corpus from a json file."""
    with open(filename, 'r') as f:
      corpus_data = jsonpickle.decode(f.read())

    seeds_data = corpus_data['seeds_data']
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
                  signals=[SignalType[s] for s in seed_data['signals']],
                  lengths=seed_data['lengths'],
                  widths=seed_data['widths'])
      self.seeds.append(seed)

    self.config = corpus_data['config']


  def add(self, seed):
    self.seeds.append(seed)



