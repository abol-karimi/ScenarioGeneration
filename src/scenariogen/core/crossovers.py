import itertools
from random import Random
import geomdl
from geomdl import BSpline
import numpy as np
import shapely
from scenic.domains.driving.roads import LinearElement, Network
from scenic.core.regions import PolygonalRegion, PolylineRegion
from scenic.core.vectors import Vector

# This project
import src.scenariogen.core.utils as utils
from src.scenariogen.core.signals import SignalType
from scenariogen.core.seed import Seed, Spline

class StructureAwareCrossOver():
  """Randomly combine trajectories from two different seeds.
  
  Guarantees:
  * Vehicles never back up,
  i.e. the velocity and heading vectors make an acute angle.

  * Conservation of matter,
  i.e. vehicles don't spawn or disappear after a scenario starts till it ends.

  * The created scenarios' durations don't exceed config['maxSeconds']

  """
  _networks_cache = {}
  _route_lengths_cache = {}
  _predecessors_cache = {}

  def __init__(self, max_parameters_size=50,
                      max_attempts=1,
                      randomizer_seed=0):
    self.max_parameters_size = max_parameters_size
    self.max_attempts = max_attempts
    self.randomizer_seed = randomizer_seed

    self.random = Random(randomizer_seed)
    self.crossOvers = [ self.population_splice,
                      #  self.trajectory_splice
                    ]

  def cross_over(self, seed1, seed2):
    for i in range(self.max_attempts):
      try:
        return self.random.choice(self.crossOvers)(seed1, seed2)
      except CrossOverError as err:
        print('CrossOver error: ' + err.msg)
    return self.random.choice((seed1, seed2))
  
  def population_splice(self, seed1, seed2):
    n1 = self.random.randint(1, len(seed1.routes))
    n2 = self.random.randint(1, len(seed2.routes))
    idx1 = self.random.sample(range(n1), n1)
    idx2 = self.random.sample(range(n2), n2)

    crossover = Seed(config=seed1.config,
                  routes=tuple(itertools.chain((seed1.routes[i] for i in idx1),(seed2.routes[i] for i in idx2))),
                  footprints=tuple(itertools.chain((seed1.footprints[i] for i in idx1),(seed2.footprints[i] for i in idx2))),
                  timings=tuple(itertools.chain((seed1.timings[i] for i in idx1),(seed2.timings[i] for i in idx2))),
                  signals=tuple(itertools.chain((seed1.signals[i] for i in idx1),(seed2.signals[i] for i in idx2))),
                  lengths=tuple(itertools.chain((seed1.lengths[i] for i in idx1),(seed2.lengths[i] for i in idx2))),
                  widths=tuple(itertools.chain((seed1.widths[i] for i in idx1),(seed2.widths[i] for i in idx2))),
                  )
    print(f'Population-splice crossover: {n1} cars from seed1 and {n2} cars from seed2.')
    return crossover
  
  def trajectory_splice(self, seed1, seed2):
    # TODO
    return
  
  @classmethod
  def get_network(cls, seed):
    carla_map = seed.config['carla_map']
    if not carla_map in cls._networks_cache:
      network = Network.fromFile(seed.config['map'])
      cls._networks_cache[carla_map] = network
      cls._cache_predessors(carla_map, network)
      return network
    else:
      return cls._networks_cache[carla_map]
  
  @classmethod
  def _cache_predessors(cls, carla_map, network):
    cls._predecessors_cache[carla_map] = {m.endLane.uid: [] for intersection in network.intersections for m in intersection.maneuvers}
    for intersection in network.intersections:
      for maneuver in intersection.maneuvers:
        cls._predecessors_cache[carla_map][maneuver.endLane.uid].append(maneuver.connectingLane)
    
  
class CrossOverError(Exception):
    """Exception raised for errors in crossing over two seeds.
    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.msg = message