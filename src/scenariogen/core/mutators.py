from random import Random
import copy
import geomdl
from geomdl import BSpline
import numpy as np
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
                    self.add_controlpoint,
                    self.remove_controlpoint,
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
    nonego_idx = self.random.randrange(len(seed.trajectories))
    
    route = seed.routes[nonego_idx]
    traj = seed.trajectories[nonego_idx]
    length = seed.lengths[nonego_idx]

    lanes = [RandomMutator.get_network(seed).elements[lane_id]
             for lane_id in route]
    min_dist = length
    max_dist = 20 # TODO change to the distance of the last control point to the end of the route
    # TODO return if min_dist > max_dist
    delta = self.random.uniform(min_dist, max_dist)
    route_region = LinearElement(
      id=f'route_{lanes}_{delta}',
      polygon=PolygonalRegion.unionAll(lanes).polygons,
      centerline=PolylineRegion.unionAll([l.centerline for l in lanes]),
      leftEdge=PolylineRegion.unionAll([l.leftEdge for l in lanes]),
      rightEdge=PolylineRegion.unionAll([l.rightEdge for l in lanes])
      )
    ctrlpts_copy_2d = (route_region.flowFrom(Vector(p[0], p[1]), delta)
                       for p in traj.ctrlpts)
    ctrlpts_copy = tuple((pc.x, pc.y, p[2])
                          for pc, p in zip(ctrlpts_copy_2d, traj.ctrlpts))

    traj_c = Trajectory(degree=traj.degree,
                        ctrlpts=ctrlpts_copy,
                        knotvector=traj.knotvector)

    mutant = Seed(config=seed.config,
                  routes=seed.routes+(route,),
                  trajectories=seed.trajectories+(traj_c,),
                  signals=seed.signals+(seed.signals[nonego_idx],),
                  lengths=seed.lengths+(length,),
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
                  trajectories=seed.trajectories[0:nonego_idx]+seed.trajectories[nonego_idx+1:],
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
  
  def move_first_controlpoint_vertically(self, seed):
    """Move the first control-point (of a random car) vertically in the t-d plane.
    """
    print('Moving the first control point vertically...')
    mutant = copy.deepcopy(seed)
    nonego_idx = self.random.randrange(len(mutant.routes))
    ctrlpts = mutant.trajectories[nonego_idx].ctrlpts
    t0, d1 = ctrlpts[0][0], ctrlpts[1][1]
    ctrlpts[0] = (t0, self.random.uniform(0, d1))
    return mutant

  def move_last_controlpoint_vertically(self, seed):
    """Move the last control-point (of a random car) vertically in the t-d plane.
    """
    print('Moving the first control point vertically...')
    mutant = copy.deepcopy(seed)
    nonego_idx = self.random.randrange(len(mutant.routes))
    ctrlpts = mutant.trajectories[nonego_idx].ctrlpts
    ctrlpts[-1][1] = self.random.uniform(ctrlpts[-2][1], self.route_lengths[nonego_idx])
    return mutant

  def move_mid_controlpoint_vertically(self, seed):
    """Move an intermediate control-point vertically (in the t-d plane).
    """
    print('Moving an intermediate control point vertically...')
    mutant = copy.deepcopy(seed)
    nonego_idx = self.random.randrange(len(mutant.routes))
    curve = mutant.trajectories[nonego_idx]
    ctrlpts = curve.ctrlpts
    p_idx = self.random.randrange(1, len(ctrlpts)-1)
    ctrlpts[p_idx][1] = self.random.uniform(ctrlpts[p_idx-1][1], ctrlpts[p_idx+1][1])
    return mutant

  def add_controlpoint(self, seed):
    """Selects a random vehicle, then
    adds a control point at a random position in the curve.
    """
    nonego_idx = self.random.randrange(len(seed.routes))
    traj = seed.trajectories[nonego_idx]
    if len(traj.ctrlpts) == self.max_parameters_size:
      raise MutationError('Cannot add any more controlpoints to the traj!')
    t = self.random.uniform(traj.ctrlpts[0][2], traj.ctrlpts[-1][2])
    
    # Make a geomdl Spline, insert a knot, then extract the parameters to a Trajectory
    spline = BSpline.Curve(normalize_kv = False)
    spline.degree = traj.degree
    spline.ctrlpts = traj.ctrlpts
    spline.knotvector = traj.knotvector
    spline.insert_knot(t)

    traj_mutated = Trajectory(degree=spline.degree,
                              ctrlpts=tuple(tuple(ctrlpt) for ctrlpt in spline.ctrlpts),
                              knotvector=tuple(spline.knotvector)
                              )

    mutant = Seed(config=seed.config,
                  routes=seed.routes,
                  trajectories=
                    seed.trajectories[0:nonego_idx] \
                    + (traj_mutated,) \
                    + seed.trajectories[nonego_idx+1:],
                  signals=seed.signals,
                  lengths=seed.lengths,
                  widths=seed.widths
                  )
  
    return mutant

  def remove_controlpoint(self, seed):
    """Selects a random vehicle, then
    removes a random control point from the curve.
    """
    nonego_idx = self.random.randrange(len(seed.routes))
    traj = seed.trajectories[nonego_idx]
    endpoint_knots = traj.degree + 1
    if len(traj.knotvector) <= 2*endpoint_knots:
      raise MutationError('Not enough controlpoints to remove!')
    knot = self.random.choice(traj.knotvector[endpoint_knots:-endpoint_knots])

    # Make a geomdl Spline, remove the knot, then extract the parameters to a Trajectory
    spline = BSpline.Curve(normalize_kv = False)
    spline.degree = traj.degree
    spline.ctrlpts = traj.ctrlpts
    spline.knotvector = list(traj.knotvector)
    spline.remove_knot(knot)

    traj_mutated = Trajectory(degree=spline.degree,
                              ctrlpts=tuple(tuple(ctrlpt) for ctrlpt in spline.ctrlpts),
                              knotvector=tuple(spline.knotvector)
                              )
    mutant = Seed(config=seed.config,
                  routes=seed.routes,
                  trajectories=
                    seed.trajectories[0:nonego_idx] \
                    + (traj_mutated,) \
                    + seed.trajectories[nonego_idx+1:],
                  signals=seed.signals,
                  lengths=seed.lengths,
                  widths=seed.widths
                  )
    return mutant

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