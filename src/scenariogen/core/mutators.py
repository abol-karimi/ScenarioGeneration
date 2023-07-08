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

class RandomMutator():
  """Randomly change the the trajectories using their parameters.
  
  Guarantees:
  * Vehicles never back up,
  i.e. the velocity and heading vectors make an acute angle.

  * Conservation of matter,
  i.e. vehicles don't spawn or disappear after a scenario starts till it ends.

  * The created scenarios' durations don't exceed config['maxSeconds']

  """
  _networks_cache = {}
  _route_lengths_cache = {}

  def __init__(self, max_parameters_size=50,
                      max_mutations_per_iteration=1,
                      randomizer_seed=0):
    self.max_parameters_size = max_parameters_size
    self.max_mutations_per_iteration = max_mutations_per_iteration
    self.randomizer_seed = randomizer_seed

    self.random = Random(randomizer_seed)
    self.mutators = [self.copy_lon,
                     # self.move_lon,
                    self.remove_vehicle,
                    self.speedup,
                    self.slowdown,
                    # self.mutate_ego_route,
                    # self.move_first_controlpoint_vertically,
                    # self.move_last_controlpoint_vertically,
                    # self.move_mid_controlpoint_vertically,                    
                    ]
  @classmethod
  def get_network(cls, seed):
    carla_map = seed.config['carla_map']
    if not carla_map in cls._networks_cache:
      network = Network.fromFile(seed.config['map'])
      cls._networks_cache[carla_map] = network
      return network
    else:
      return cls._networks_cache[carla_map]
  def copy_lon(self, seed):
    """Copy a trajectory and add some longitudinal offset along the route.
    """
    print('Copying a vehicle and adding to the seed...')
    # Choose a random vehicle and a random longitudinal offset
    nonego_idx = self.random.randrange(len(seed.routes))
    max_dist = 100
    offset = self.random.uniform(seed.lengths[nonego_idx], max_dist)

  def copy_lon_with_params(self, seed, nonego_idx, offset):
    """Copy a trajectory and add some longitudinal offset along the route.
    """
    # Extend the route if necessary
    network = RandomMutator.get_network(seed)
    route = seed.routes[nonego_idx]
    lanes = [network.elements[lane_id]
             for lane_id in route]
    centerline = PolylineRegion.unionAll([l.centerline for l in lanes])
    p0 = seed.positions[nonego_idx].ctrlpts[0]
    available = shapely.ops.split(centerline.lineString, centerline.project(p0)).geoms[-1].length
    if offset >= available - 10: # 10 meters cushion
      # Extend the route by offset-available+10
      ext = [self.random.choice(lanes[-1].maneuvers).connectingLane]
      ext_len = ext[-1].length
      while ext_len < offset-available+10:
        ext.append(self.random.choice(ext[-1].maneuvers).connectingLane)
        ext_len += ext[-1].length
      lanes += ext
    
    route_region = LinearElement(
      id=f'route_{lanes}',
      polygon=PolygonalRegion.unionAll(lanes).polygons,
      centerline=PolylineRegion.unionAll([l.centerline for l in lanes]),
      leftEdge=PolylineRegion.unionAll([l.leftEdge for l in lanes]),
      rightEdge=PolylineRegion.unionAll([l.rightEdge for l in lanes])
      )
    
    ctrlpts_moved = tuple(route_region.flowFrom(Vector(p[0], p[1]), offset)
                          for p in seed.positions[nonego_idx].ctrlpts)

    position = Spline(degree=seed.positions[nonego_idx].degree,
                    ctrlpts=tuple((p.x, p.y) for p in ctrlpts_moved),
                    knotvector=seed.positions[nonego_idx].knotvector)

    mutant = Seed(config=seed.config,
                  routes=seed.routes+((l.uid for l in lanes),),
                  positions=seed.positions+(position,),
                  timings=seed.timings+(seed.timings[nonego_idx],),
                  signals=seed.signals+(seed.signals[nonego_idx],),
                  lengths=seed.lengths+(seed.lengths[nonego_idx],),
                  widths=seed.widths+(seed.widths[nonego_idx],)
                  )
    return mutant
  
  def remove_vehicle(self, seed):
    """Removes a random non-ego from the scenario.
    """
    print('removing vehicle from the seed...')
    if len(seed.routes) == 1:
      raise MutationError('Cannot remove the singleton nonego, empty scenarios are not allowed!')
    nonego_idx = self.random.randrange(len(seed.routes))
    mutant = Seed(config=seed.config,
                  routes=seed.routes[0:nonego_idx]+seed.routes[nonego_idx+1:],
                  positions=seed.positions[0:nonego_idx]+seed.positions[nonego_idx+1:],
                  timings=seed.timings[0:nonego_idx]+seed.timings[nonego_idx+1:],                  
                  signals=seed.signals[0:nonego_idx]+seed.signals[nonego_idx+1:],
                  lengths=seed.lengths[0:nonego_idx]+seed.lengths[nonego_idx+1:],
                  widths=seed.widths[0:nonego_idx]+seed.widths[nonego_idx+1:]
                  )
    return mutant

  def speedup_with_params(self, seed, nonego_idx, interval, factor):
    timing = seed.timings[nonego_idx]

    spline = BSpline.Curve(normalize_kv = False)
    spline.degree = timing.degree
    spline.ctrlpts = timing.ctrlpts
    spline.knotvector = timing.knotvector

    # Move the corresponding controlpoints vertically up
    d_min = geomdl.operations.find_ctrlpts(spline, interval[0])[-1][1]
    d_max = geomdl.operations.find_ctrlpts(spline, interval[1])[0][1]
    interval_ctrlpts = tuple(p for p in spline.ctrlpts if p[1] >= d_min and p[1] <= d_max)
    for pi, pii in zip(reversed(interval_ctrlpts[:-1]), reversed(interval_ctrlpts[1:])):
      pi[1] = (1-factor)*pi[1] + factor*pii[1]

    # Construct the new seed
    timing_mutated = Spline(degree=timing.degree,
                              ctrlpts=tuple(tuple(ctrlpt) for ctrlpt in spline.ctrlpts),
                              knotvector=tuple(spline.knotvector)
                              )
    
    mutant = Seed(config=seed.config,
                  routes=seed.routes,
                  positions=seed.positions,
                  timings=
                    seed.timings[0:nonego_idx] \
                    + (timing_mutated,) \
                    + seed.timings[nonego_idx+1:],
                  signals=seed.signals,
                  lengths=seed.lengths,
                  widths=seed.widths
                  )
  
    return mutant

  def speedup(self, seed):
    """Speeds up a random nonego over a random time interval [a, b].
    """
    print('Speeding up a nonego over an interval...')
    nonego_idx = self.random.randrange(len(seed.routes))

    # Choose a random interval
    timing = seed.timings[nonego_idx]
    a = self.random.uniform(0, timing.ctrlpts[-1][1])
    b = self.random.uniform(a, timing.ctrlpts[-1][1])

    # Speed up factor
    factor = self.random.uniform(.1, .9)

    return self.speedup_with_params(seed, nonego_idx, (a, b), factor)

  def slowdown_with_params(self, seed, nonego_idx, interval, factor):
    timing = seed.timings[nonego_idx]

    spline = BSpline.Curve(normalize_kv = False)
    spline.degree = timing.degree
    spline.ctrlpts = timing.ctrlpts
    spline.knotvector = timing.knotvector

    # Move the corresponding controlpoints vertically down
    d_min = geomdl.operations.find_ctrlpts(spline, interval[0])[-1][1]
    d_max = geomdl.operations.find_ctrlpts(spline, interval[1])[0][1]
    interval_ctrlpts = tuple(p for p in spline.ctrlpts if p[1] >= d_min and p[1] <= d_max)
    for pi, pii in zip(interval_ctrlpts[:-1], interval_ctrlpts[1:]):
      pii[1] = factor*pi[1] + (1-factor)*pii[1]

    # Construct the new seed
    timing_mutated = Spline(degree=timing.degree,
                            ctrlpts=tuple(tuple(ctrlpt) for ctrlpt in spline.ctrlpts),
                            knotvector=tuple(spline.knotvector)
                            )

    mutant = Seed(config=seed.config,
                  routes=seed.routes,
                  positions=seed.positions,
                  timings=
                    seed.timings[0:nonego_idx] \
                    + (timing_mutated,) \
                    + seed.timings[nonego_idx+1:],
                  signals=seed.signals,
                  lengths=seed.lengths,
                  widths=seed.widths
                  )
  
    return mutant
  
  def slowdown(self, seed):
    print('Slowing down a nonego over an interval...')
    nonego_idx = self.random.randrange(len(seed.routes))

    # Choose a random interval
    timing = seed.timings[nonego_idx]
    a = self.random.uniform(0, timing.ctrlpts[-1][1])
    b = self.random.uniform(a, timing.ctrlpts[-1][1])

    # Speed up factor
    factor = self.random.uniform(.1, .9)

    return self.slowdown_with_params(seed, nonego_idx, (a, b), factor)
  
  def mutate_ego_route(self, seed):
    """Used for closed-loop fuzzing."""
    return seed
  

  def mutate(self, seed):
    mutant = seed
    mutations = self.random.randint(1, self.max_mutations_per_iteration)
    for i in range(mutations):
      mutator = self.random.choice(self.mutators)
      try:
        mutant = mutator(mutant)
      except MutationError as err:
        print('Mutation error: ' + err.msg)
    return mutant
    
    

class MutationError(Exception):
    """Exception raised for errors in mutating a seed.
    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.msg = message