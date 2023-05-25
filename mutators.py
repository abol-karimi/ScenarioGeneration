import random
import copy
from geomdl import BSpline
import numpy as np
from scenic.domains.driving.roads import LinearElement, Network
from scenic.core.regions import PolygonalRegion, PolylineRegion
from scenic.core.vectors import Vector

# This project
import utils
from signals import SignalType
from seed_corpus import Route

class RandomMutator():
  """Randomly change the the trajectories using their parameters.
  
  Guarantees:
  * Vehicles never back up,
  i.e. the velocity and heading vectors make an acute angle.

  * Conservation of matter,
  i.e. vehicles don't spawn or disappear after a scenario starts till it ends.

  * The created scenarios' durations don't exceed config['maxSeconds']

  """
  def __init__(self, config):
    network = Network.fromFile(config['map'])
    intersection = network.elements[config['intersection']]
    routes = [(m.startLane, m.connectingLane, m.endLane)
              for m in intersection.maneuvers]

    self.config = config
    self.network = network
    self.intersection = intersection
    self.routes = routes
    self.route_lengths = [utils.route_length(r) for r in routes]
    self.mutators = [self.copy_lon,
                    # self.invalid,        
                    # self.remove_vehicle,
                    # self.add_slowdown,
                    # self.move_first_controlpoint_vertically,
                    # self.move_last_controlpoint_vertically,
                    # self.move_mid_controlpoint_vertically,
                    self.add_controlpoint,
                    self.remove_controlpoint
                    ]

  def invalid(self, seed):
    """Creates an invalid scenario for debugging.
    """
    print('Creating an invalid scenario...')
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.trajectories))
    
    route = mutant.routes[nonego_idx]
    traj = mutant.trajectories[nonego_idx]
    lanes = [self.network.elements[lane_id] 
             for lane_id in route.lanes]
    delta = 2
    route_region = LinearElement(
      id=f'route_{lanes}_{delta}',
      polygon=PolygonalRegion.unionAll(lanes).polygons,
      centerline=PolylineRegion.unionAll([l.centerline for l in lanes]),
      leftEdge=PolylineRegion.unionAll([l.leftEdge for l in lanes]),
      rightEdge=PolylineRegion.unionAll([l.rightEdge for l in lanes])
      )
    ctrlpts_copy_2d = [route_region.flowFrom(Vector(p[0], p[1]), delta)
                       for p in traj.ctrlpts]
    ctrlpts_copy = [[pc.x, pc.y, p[2]]
                    for pc, p in zip(ctrlpts_copy_2d, traj.ctrlpts)]

    traj_c = BSpline.Curve(normalize_kv = False)
    traj_c.degree = traj.degree
    traj_c.ctrlpts = ctrlpts_copy
    traj_c.knotvector = [k for k in traj.knotvector]

    mutant.routes.append(copy.deepcopy(route))
    mutant.trajectories.append(traj_c)
    mutant.signals.append(mutant.signals[nonego_idx])
    return mutant
  
  def copy_lon(self, seed):
    """Copy a trajectory and add some longitudinal offset along the route.
    """
    print('Copying a vehicle and adding to the seed...')
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.trajectories))
    
    route = mutant.routes[nonego_idx]
    traj = mutant.trajectories[nonego_idx]
    length = mutant.lengths[nonego_idx]

    lanes = [self.network.elements[lane_id] 
             for lane_id in route.lanes]
    min_dist = length
    max_dist = 20 # TODO change to the distance of the last control point to the end of the route
    # TODO return if min_dist > max_dist
    delta = random.uniform(min_dist, max_dist)
    route_region = LinearElement(
      id=f'route_{lanes}_{delta}',
      polygon=PolygonalRegion.unionAll(lanes).polygons,
      centerline=PolylineRegion.unionAll([l.centerline for l in lanes]),
      leftEdge=PolylineRegion.unionAll([l.leftEdge for l in lanes]),
      rightEdge=PolylineRegion.unionAll([l.rightEdge for l in lanes])
      )
    ctrlpts_copy_2d = [route_region.flowFrom(Vector(p[0], p[1]), delta)
                       for p in traj.ctrlpts]
    ctrlpts_copy = [[pc.x, pc.y, p[2]]
                    for pc, p in zip(ctrlpts_copy_2d, traj.ctrlpts)]

    traj_c = BSpline.Curve(normalize_kv = False)
    traj_c.degree = traj.degree
    traj_c.ctrlpts = ctrlpts_copy
    traj_c.knotvector = [k for k in traj.knotvector]

    mutant.routes.append(copy.deepcopy(route))
    mutant.trajectories.append(traj_c)
    mutant.signals.append(mutant.signals[nonego_idx])
    mutant.lengths.append(length)
    mutant.widths.append(mutant.widths[nonego_idx])
    return mutant
  
  def remove_vehicle(self, seed):
    """Removes a random non-ego from the scenario.
    """
    print('removing vehicle from the seed...')
    if len(seed.routes) == 1:
      raise MutationError('Empty seeds are not allowed!')
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    mutant.routes.pop(nonego_idx)
    mutant.trajectories.pop(nonego_idx)
    mutant.signals.pop(nonego_idx)
    return mutant

  def move_first_controlpoint_vertically(self, seed):
    """Move the first control-point (of a random car) vertically in the t-d plane.
    """
    print('Moving the first control point vertically...')
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    ctrlpts = mutant.trajectories[nonego_idx].ctrlpts
    t0, d1 = ctrlpts[0][0], ctrlpts[1][1]
    ctrlpts[0] = [t0, random.uniform(0, d1)]
    return mutant

  def move_last_controlpoint_vertically(self, seed):
    """Move the last control-point (of a random car) vertically in the t-d plane.
    """
    print('Moving the first control point vertically...')
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    ctrlpts = mutant.trajectories[nonego_idx].ctrlpts
    ctrlpts[-1][1] = random.uniform(ctrlpts[-2][1], self.route_lengths[nonego_idx])
    return mutant

  def move_mid_controlpoint_vertically(self, seed):
    """Move an intermediate control-point vertically (in the t-d plane).
    """
    print('Moving an intermediate control point vertically...')
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    curve = mutant.trajectories[nonego_idx]
    ctrlpts = curve.ctrlpts
    p_idx = random.randrange(1, len(ctrlpts)-1)
    ctrlpts[p_idx][1] = random.uniform(ctrlpts[p_idx-1][1], ctrlpts[p_idx+1][1])
    return mutant

  def add_controlpoint(self, seed):
    """Selects a random vehicle, then
    adds a control point at a random position in the curve.
    """
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    curve = mutant.trajectories[nonego_idx]
    if len(curve.ctrlpts) == self.config['max_parameters_size']:
      raise MutationError('Cannot add any more controlpoints to the curve!')
    t = random.uniform(curve.ctrlpts[0][2], curve.ctrlpts[-1][2])
    curve.insert_knot(t)
    return mutant

  def remove_controlpoint(self, seed):
    """Selects a random vehicle, then
    removes a random control point from the curve.
    """
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    curve = mutant.trajectories[nonego_idx]
    endpoint_knots = curve.degree + 1
    if len(curve.knotvector) <= 2*endpoint_knots:
      raise MutationError('Not enough controlpoints to remove!')
    knot = random.choice(curve.knotvector[endpoint_knots:-endpoint_knots])
    curve.remove_knot(knot)
    return mutant

  def mutate(self, seed):
    mutant = seed
    mutations = random.randint(1, self.config['max_mutations_per_iteration'])
    for i in range(mutations):
      mutator = random.choice(self.mutators)
      try:
        mutant = mutator(mutant)
      except MutationError as err:
        print('Mutation error: ' + err.message)
    return mutant
    
    

class MutationError(Exception):
    """Exception raised for errors in mutating a seed.
    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message