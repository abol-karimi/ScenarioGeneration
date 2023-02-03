import random
import copy
from geomdl import BSpline
import numpy as np

# This project
import utils
from signals import SignalType
from seed_corpus import Route

class RandomMutator():
  def __init__(self, config):
    network = config['network']
    intersection = network.elements[config['intersection_uid']]
    routes = [(m.startLane, m.connectingLane, m.endLane)
              for m in intersection.maneuvers]
    final_time = config['maxSteps']*config['timestep']

    self.config = config
    self.network = network
    self.intersection = intersection
    self.routes = routes
    self.route_lengths = [utils.route_length(r) for r in routes]
    self.final_time = final_time
    self.mutators = [self.add_vehicle,
                    self.remove_vehicle,
                    self.move_first_controlpoint_vertically,
                    self.move_last_controlpoint_vertically,
                    self.move_mid_controlpoint_vertically,
                    self.add_controlpoint,
                    self.remove_controlpoint
                    ]

  def add_vehicle(self, seed):
    """Adds a non-ego to the scenario, using a random route through the intersection,
    and starting at a random location along the route.
    """
    print('Adding vehicle to the seed...')
    mutant = copy.deepcopy(seed)
    idx = random.randrange(len(self.routes))
    route = self.routes[idx]
    degree = self.config['interpolation_degree']
    D = self.route_lengths[idx]
    D1 = random.uniform(0, D)
    D2 = random.uniform(D1, D)
    T = self.final_time
    ts = [T*i/degree for i in range(degree+1)]
    ds = [D1 + (D2-D1)*i/degree for i in range(degree+1)]
    curve = BSpline.Curve(normalize_kv = False)
    curve.degree = degree
    curve.ctrlpts = [[t, d] for t,d in zip(ts,ds)]
    curve.knotvector = [ts[0] for i in range(degree)] \
                  + list(np.linspace(ts[0], ts[-1], num=len(ts)-degree+1)) \
                  + [ts[-1] for i in range(degree)]
    signal = random.choice(list(SignalType))

    mutant.routes.append(Route(lanes=[l.uid for l in route]))
    mutant.curves.append(curve)
    mutant.signals.append(signal)
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
    mutant.curves.pop(nonego_idx)
    mutant.signals.pop(nonego_idx)
    return mutant

  def move_first_controlpoint_vertically(self, seed):
    """Move the first control-point (of a random car) vertically in the t-d plane.
    """
    print('Moving the first control point vertically...')
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    ctrlpts = mutant.curves[nonego_idx].ctrlpts
    t0, d1 = ctrlpts[0][0], ctrlpts[1][1]
    ctrlpts[0] = [t0, random.uniform(0, d1)]
    return mutant

  def move_last_controlpoint_vertically(self, seed):
    """Move the last control-point (of a random car) vertically in the t-d plane.
    """
    print('Moving the first control point vertically...')
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    ctrlpts = mutant.curves[nonego_idx].ctrlpts
    ctrlpts[-1][1] = random.uniform(ctrlpts[-2][1], self.route_lengths[nonego_idx])
    return mutant

  def move_mid_controlpoint_vertically(self, seed):
    """Move an intermediate control-point vertically (in the t-d plane).
    """
    print('Moving an intermediate control point vertically...')
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    curve = mutant.curves[nonego_idx]
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
    curve = mutant.curves[nonego_idx]
    if len(curve.ctrlpts) == self.config['max_ctrlpts']:
      raise MutationError('Cannot add any more controlpoints to the curve!')
    t = random.randrange(curve.ctrlpts[0][0], curve.ctrlpts[-1][0])
    curve.insert_knot(t)
    return mutant

  def remove_controlpoint(self, seed):
    """Selects a random vehicle, then
    removes a random control point from the curve.
    """
    mutant = copy.deepcopy(seed)
    nonego_idx = random.randrange(len(mutant.routes))
    curve = mutant.curves[nonego_idx]
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