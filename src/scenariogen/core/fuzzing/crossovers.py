import itertools
from random import Random
import geomdl
from geomdl import BSpline
import numpy as np
import shapely
from scenic.domains.driving.roads import LinearElement, Network
from scenic.core.regions import PolygonalRegion, PolylineRegion

# This project
import src.scenariogen.core.utils as utils
from src.scenariogen.core.signals import SignalType
from scenariogen.core.fuzz_input import FuzzInput, Spline

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

  def __init__(self, max_spline_knots_size=50,
                      max_attempts=1,
                      randomizer_seed=0):
    self.max_spline_knots_size = max_spline_knots_size
    self.max_attempts = max_attempts
    self.randomizer_seed = randomizer_seed

    self.random = Random(randomizer_seed)
    self.crossOvers = [ self.population_splice,
                      #  self.trajectory_splice
                    ]

  def get_state(self):
    return self.random.getstate()
  
  def set_state(self, state):
    self.random.setstate(state)

  def cross_over(self, input1, input2):
    for i in range(self.max_attempts):
      try:
        return self.random.choice(self.crossOvers)(input1, input2)
      except CrossOverError as err:
        print('CrossOver error: ' + err.msg)
    return self.random.choice((input1, input2))
  
  def population_splice(self, input1, input2):
    n1 = self.random.randint(1, len(input1.routes))
    n2 = self.random.randint(1, len(input2.routes))
    idx1 = self.random.sample(range(n1), n1)
    idx2 = self.random.sample(range(n2), n2)

    crossover = FuzzInput(config=input1.config,
                  blueprints=tuple(itertools.chain((input1.blueprints[i] for i in idx1),(input2.blueprints[i] for i in idx2))),
                  routes=tuple(itertools.chain((input1.routes[i] for i in idx1),(input2.routes[i] for i in idx2))),
                  footprints=tuple(itertools.chain((input1.footprints[i] for i in idx1),(input2.footprints[i] for i in idx2))),
                  timings=tuple(itertools.chain((input1.timings[i] for i in idx1),(input2.timings[i] for i in idx2))),
                  signals=tuple(itertools.chain((input1.signals[i] for i in idx1),(input2.signals[i] for i in idx2)))
                  )
    print(f'Population-splice crossover: {n1} cars from input1 and {n2} cars from input2.')
    return crossover
  
  def trajectory_splice(self, input1, input2):
    # TODO
    return
  
  @classmethod
  def get_network(cls, seed):
    carla_map = seed.config['carla_map']
    if not carla_map in cls._networks_cache:
      network = Network.fromFile(seed.config['map'])
      cls._networks_cache[carla_map] = network
      cls._cache_predecessors(carla_map, network)
      return network
    else:
      return cls._networks_cache[carla_map]
  
  @classmethod
  def _cache_predecessors(cls, carla_map, network):
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