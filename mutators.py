import random
import copy
from geomdl import BSpline
import numpy as np

# This project
import utils
from signals import SignalType
from seed import Route

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
                    self.add_controlpoint
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
    mutant = copy.deepcopy(seed)
    idx = random.randrange(len(mutant.routes))
    mutant.routes.pop(idx)
    mutant.curves.pop(idx)
    mutant.signals.pop(idx)
    return mutant

  def move_first_controlpoint_vertically(self, seed):
    """Move the first control-point (of a random car) vertically in the t-d plane.
    """
    print('Moving the first control point vertically...')
    mutant = copy.deepcopy(seed)
    idx = random.randrange(len(mutant.routes))
    ctrlpts = mutant.curves[idx].ctrlpts
    t0, d1 = ctrlpts[0][0], ctrlpts[1][1]
    ctrlpts[0] = [t0, random.uniform(0, d1)]
    return mutant

  def move_last_controlpoint_vertically(self, seed):
    """Move the last control-point (of a random car) vertically in the t-d plane.
    """
    print('Moving the first control point vertically...')
    mutant = copy.deepcopy(seed)
    idx = random.randrange(len(mutant.routes))
    ctrlpts = mutant.curves[idx].ctrlpts
    ctrlpts[-1][1] = random.uniform(ctrlpts[-2][1], self.route_lengths[idx])
    return mutant

  def move_mid_controlpoint_vertically(self, seed):
    """Move an intermediate control-point vertically (in the t-d plane).
    """
    print('Moving an intermediate control point vertically...')
    mutant = copy.deepcopy(seed)
    idx = random.randrange(len(mutant.routes))
    ctrlpts = mutant.curves[idx].ctrlpts
    p_idx = random.randrange(1, len(ctrlpts)-1)
    ctrlpts[p_idx][1] = random.uniform(ctrlpts[p_idx-1][1], ctrlpts[p_idx+1][1])
    return mutant


  # def move_controlpoint_horizontally(self, seed):
  #   """Move a control-point horizontally (in the t-d plane).
  #   """
  #   print('Moving a control point horizontally...')
  #   mutant = copy.deepcopy(seed)
  #   v_idx = random.randrange(len(mutant.routes))
  #   ctrlpts = mutant.curves[v_idx].ctrlpts
  #   p_idx = random.randrange(len(ctrlpts))
  #   ctrlpts[p_idx] = [ctrlpts[p_idx][0]+random.uniform(-1, 1),
  #                     ctrlpts[p_idx][1]]
  #   return mutant

  def add_controlpoint(self, seed):
    """Selects a random vehicle, then
    adds a control point at a random position in the composite curve.
    """
    mutant = copy.deepcopy(seed)
    valid_indices = [i for i in range(len(mutant.curves))
                      if len(mutant.curves[i].ctrlpts) < self.config['interpolation_max_ctrlpts']]
    nonego_idx = random.choice(valid_indices)
    curve = mutant.curves[nonego_idx]
    t = random.randrange(curve.ctrlpts[0][0], curve.ctrlpts[-1][0])
    curve.insert_knot(t)
    return mutant

  def mutate(self, seed):
    while True:
      mutator = random.choice(self.mutators)
      mutant = mutator(seed)
      if mutant.is_valid():
        break
    return mutant
    
    

