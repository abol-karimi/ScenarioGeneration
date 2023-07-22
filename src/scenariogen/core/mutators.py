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

class StructureAwareMutator():
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
  _predecessors_cache = {}

  def __init__(self, max_parameters_size=50,
                      max_mutations_per_iteration=1,
                      randomizer_seed=0):
    self.max_parameters_size = max_parameters_size
    self.max_mutations_per_iteration = max_mutations_per_iteration
    self.randomizer_seed = randomizer_seed

    self.random = Random(randomizer_seed)
    self.mutators = [self.copy_forward,
                     self.copy_backward,
                     self.move_forward,
                     self.move_backward,
                     self.change_route,
                     self.copy_to_route,
                     self.remove_vehicle,
                     self.speedup,
                     self.slowdown,
                    # self.change_ego_route,                 
                    ]
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

 
  def move_forward(self, seed):
    """Adds some longitudinal offset to a trajectory along its route.
    Extends the route randomly, if necessay.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(seed.routes))
    max_dist = 100
    offset = self.random.uniform(seed.lengths[nonego_idx], max_dist)

    # Mutate
    mutant = self.copy_forward_with_params(seed, nonego_idx, offset)
    mutant = self.remove_vehicle(mutant)

    print(f'Mutation: Moved nonego {nonego_idx} forward along its route by {offset} meters.')

    return mutant
  
  def copy_forward_with_params(self, seed, nonego_idx, offset):
    # Move the trajectory, extend the route if necessary
    network = StructureAwareMutator.get_network(seed)
    lanes = [network.elements[lane_id]
             for lane_id in seed.routes[nonego_idx]]
    centerline = shapely.geometry.MultiLineString([l.centerline.points for l in lanes])
    footprint = seed.footprints[nonego_idx]
    available = centerline.length - footprint.ctrlpts[-1][0]
    if offset > available - 10: # 10 meters cushion
      # Extend the route by offset-available+10
      lanes += self._extend_lanes_forward(lanes, offset-available+10)
      print(f'Extended the route forward by {offset-available+10} meters.')

    new_footprint =  Spline(degree=footprint.degree,
                           ctrlpts=tuple((p[0]+offset, p[1]) for p in footprint.ctrlpts),
                           knotvector=footprint.knotvector)
    new_route = tuple(l.uid for l in lanes)

    mutant = Seed(config=seed.config,
                  routes=seed.routes+(new_route,),
                  footprints=seed.footprints+(new_footprint,),
                  timings=seed.timings+(seed.timings[nonego_idx],),
                  signals=seed.signals+(seed.signals[nonego_idx],),
                  lengths=seed.lengths+(seed.lengths[nonego_idx],),
                  widths=seed.widths+(seed.widths[nonego_idx],)
                  )
    return mutant
    
  def copy_forward(self, seed):
    """Copy a trajectory and add some longitudinal offset along the route.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(seed.routes))
    max_dist = 100
    offset = self.random.uniform(seed.lengths[nonego_idx], max_dist)

    # Mutate
    mutant = self.copy_forward_with_params(seed, nonego_idx, offset)

    print(f'Mutation: Copied nonego {nonego_idx} forward by {offset} meters.')

    return mutant
  
  def move_backward(self, seed):
    """Subtracts some longitudinal offset from a trajectory along its route.
    Extends the route backwards randomly, if necessay.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(seed.routes))
    max_dist = 100 # bigger than any vehicle length
    offset = self.random.uniform(seed.lengths[nonego_idx], max_dist)

    # Mutate
    mutant = self.copy_backward_with_params(seed, nonego_idx, offset)
    mutant = self.remove_vehicle_with_params(mutant, nonego_idx)

    print(f'Mutation: Moved nonego {nonego_idx} backwards by {offset} meters.')

    return mutant

  def copy_backward_with_params(self, seed, nonego_idx, offset):
    lanes = [self.get_network(seed).elements[lane_id]
             for lane_id in seed.routes[nonego_idx]]
    footprint = seed.footprints[nonego_idx]
    available = footprint.ctrlpts[0][0]
    ext_len = 0
    if offset > available - 10: # 10 meters cushion
      # Extend the route by offset-available+10
      lanes = self._extend_lanes_backward(seed.config['carla_map'], lanes, offset-available+10) + lanes
      print(f'Extended the route backwards by {offset-available+10} meters.')
    
    new_footprint = Spline(degree=footprint.degree,
                      ctrlpts=tuple((p[0]+ext_len-offset, p[1]) for p in footprint.ctrlpts),
                      knotvector=footprint.knotvector)
    new_route = tuple(l.uid for l in lanes)

    mutant = Seed(config=seed.config,
                  routes=seed.routes+(new_route,),
                  footprints=seed.footprints+(new_footprint,),
                  timings=seed.timings+(seed.timings[nonego_idx],),
                  signals=seed.signals+(seed.signals[nonego_idx],),
                  lengths=seed.lengths+(seed.lengths[nonego_idx],),
                  widths=seed.widths+(seed.widths[nonego_idx],)
                  )
    return mutant
  
  def copy_backward(self, seed):
    """Copy a trajectory and add some longitudinal offset along the route.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(seed.routes))
    max_dist = 100 # bigger than any vehicle length
    offset = self.random.uniform(seed.lengths[nonego_idx], max_dist)

    # Mutate
    mutant = self.copy_backward_with_params(seed, nonego_idx, offset)

    print(f'Mutation: Copied nonego {nonego_idx} backwards by {offset} meters.')

    return mutant
  
  def change_route(self, seed):
    """Move a trajectory to a different route.
    The local curvilinear coordinates of the control points are preserved.
    """
    # Choose a random vehicle and calculate its trajectory length
    nonego_idx = self.random.randrange(len(seed.routes))

    # Choose a random maneuver through the intersection
    network = self.get_network(seed)
    intersection = network.elements[seed.config['intersection']]
    maneuver = self.random.choice(intersection.maneuvers)
    
    mutant = self.copy_to_route_with_params(seed, nonego_idx, maneuver)
    mutant = self.remove_vehicle_with_params(mutant, nonego_idx)

    print(f'Mutation: Moved nonego {nonego_idx} to route {maneuver.startLane, maneuver.connectingLane, maneuver.endLane}.')

    return mutant
  
  def copy_to_route_with_params(self, seed, nonego_idx, maneuver):
    network = self.get_network(seed)
    old_route = seed.routes[nonego_idx]
    old_lanes = [network.elements[uid] for uid in old_route]
    old_route_len = sum((l.centerline.length for l in old_lanes))
    
    lanes = [maneuver.startLane, maneuver.connectingLane, maneuver.endLane]
    route_len = sum((l.centerline.length for l in lanes))
    if old_route_len > route_len:
      lanes += self._extend_lanes_forward(lanes, old_route_len - route_len)

    route = tuple(l.uid for l in lanes)

    mutant = Seed(config=seed.config,
                  routes=seed.routes+(route,),
                  footprints=seed.footprints+(seed.footprints[nonego_idx],),
                  timings=seed.timings+(seed.timings[nonego_idx],),
                  signals=seed.signals+(seed.signals[nonego_idx],),
                  lengths=seed.lengths+(seed.lengths[nonego_idx],),
                  widths=seed.widths+(seed.widths[nonego_idx],)
                  )
    
    return mutant

  def copy_to_route(self, seed):
    """Copy a trajectory to a different route.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(seed.routes))  
    network = self.get_network(seed)
    intersection = network.elements[seed.config['intersection']]
    maneuver = self.random.choice(intersection.maneuvers)

    # Mutate
    mutant = self.copy_to_route_with_params(seed, nonego_idx, maneuver)
    
    print(f'Mutation: Copied nonego {nonego_idx} to route {maneuver.startLane.uid, maneuver.connectingLane.uid, maneuver.endLane.uid}')

    return mutant

  def remove_vehicle_with_params(self, seed, nonego_idx):
    mutant = Seed(config=seed.config,
                  routes=seed.routes[0:nonego_idx]+seed.routes[nonego_idx+1:],
                  footprints=seed.footprints[0:nonego_idx]+seed.footprints[nonego_idx+1:],
                  timings=seed.timings[0:nonego_idx]+seed.timings[nonego_idx+1:],                  
                  signals=seed.signals[0:nonego_idx]+seed.signals[nonego_idx+1:],
                  lengths=seed.lengths[0:nonego_idx]+seed.lengths[nonego_idx+1:],
                  widths=seed.widths[0:nonego_idx]+seed.widths[nonego_idx+1:]
                  )
    return mutant
  
  def remove_vehicle(self, seed):
    """Removes a random non-ego from the scenario.
    """
    if len(seed.routes) == 1:
      raise MutationError('Cannot remove the singleton nonego, empty scenarios are not allowed!')
    
    # Choose random parameters
    nonego_idx = self.random.randrange(len(seed.routes))

    # Mutate
    mutant = self.remove_vehicle_with_params(seed, nonego_idx)
    
    print(f'Mutation: Removed nonego {nonego_idx} from the seed.')

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
                  footprints=seed.footprints,
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
    # Choose random paramters
    nonego_idx = self.random.randrange(len(seed.routes))
    timing = seed.timings[nonego_idx]
    a = self.random.uniform(0, timing.ctrlpts[-1][1])
    b = self.random.uniform(a, timing.ctrlpts[-1][1])
    factor = self.random.uniform(.1, .9)
    
    # Mutate
    mutant = self.speedup_with_params(seed, nonego_idx, (a, b), factor)

    print(f'Speed up nonego {nonego_idx} over interval {(a, b)} by a factor of {factor}.')

    return mutant

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
                  footprints=seed.footprints,
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
    # Choose random parameters
    nonego_idx = self.random.randrange(len(seed.routes))
    timing = seed.timings[nonego_idx]
    a = self.random.uniform(0, timing.ctrlpts[-1][1])
    b = self.random.uniform(a, timing.ctrlpts[-1][1])
    factor = self.random.uniform(.1, .9)

    # Mutate
    mutant = self.slowdown_with_params(seed, nonego_idx, (a, b), factor)

    print(f'Slowed down nonego {nonego_idx} over interval {(a, b)} by a factor of {factor}.')

    return mutant
  
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
  
  def _extend_lanes_forward(self, lanes, length):
    maneuver = self.random.choice(lanes[-1].maneuvers)
    ext = [maneuver.connectingLane if maneuver.connectingLane else maneuver.endLane]
    ext_len = ext[-1].centerline.length
    while ext_len < length:
      maneuver = self.random.choice(ext[-1].maneuvers)
      ext.append(maneuver.connectingLane if maneuver.connectingLane else maneuver.endLane)
      ext_len += ext[-1].centerline.length
    return ext
    
  def _extend_lanes_backward(self, carla_map, lanes, length):
    ext = [lanes[0]._predecessor if not lanes[0]._predecessor == None \
            else self.random.choice(self._predecessors_cache[carla_map][lanes[0].uid])
            ]
    ext_len = ext[-1].centerline.length
    while ext_len < length:
      ext.append(ext[-1]._predecessor if ext[-1]._predecessor \
            else self.random.choice(self._predecessors_cache[carla_map][ext[-1].uid]))
      ext_len += ext[-1].centerline.length
    ext.reverse()
    return ext
    
  
class MutationError(Exception):
    """Exception raised for errors in mutating a seed.
    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.msg = message