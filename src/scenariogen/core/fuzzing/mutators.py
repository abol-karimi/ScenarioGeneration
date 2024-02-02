import copy
from random import Random
import jsonpickle
import geomdl
from geomdl import BSpline
import shapely
import hashlib
from scenic.domains.driving.roads import Network

# This project
from scenariogen.core.utils import extend_lane_backward, extend_lane_forward
from scenariogen.core.signals import SignalType
from scenariogen.core.fuzz_input import FuzzInput, Spline

class StructureAwareMutator():
  """Randomly change the the trajectories using their parameters.
  
  Guarantees:
  * Vehicles never back up,
  i.e. the velocity and heading vectors make an acute angle.

  * Conservation of matter,
  i.e. vehicles don't spawn or disappear after a scenario starts till it ends.

  """
  _networks_cache = {}
  _route_lengths_cache = {}
  _predecessors_cache = {}

  def __init__(self, randomizer_seed):
    self.randomizer_seed = randomizer_seed

    self.random = Random(randomizer_seed)
    self.mutators = [
      self.copy_forward,
      self.copy_backward,
      self.move_forward,
      self.move_backward,
      self.change_route,
      self.copy_to_route,
      self.remove_vehicle,
      self.speedup,
      self.slowdown,
      self.mutate_ego_route,
      self.add_signal,
      self.remove_signal
    ]
    with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
      self.blueprint2dims = jsonpickle.decode(f.read())
    
    self.min_ego_distance_to_intersection = 20
    self.min_route_length = 200

  @classmethod
  def get_network(cls, fuzz_input):
    carla_map = fuzz_input.config['carla-map']
    if not carla_map in cls._networks_cache:
      network = Network.fromFile(fuzz_input.config['map'])
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

  def get_state(self):
    return self.random.getstate()
  
  def set_state(self, state):
    self.random.setstate(state)
  
  def move_forward(self, fuzz_input):
    """Adds some longitudinal offset to a trajectory along its route.
    Extends the route randomly, if necessay.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))
    max_dist = 100
    car_length = self.blueprint2dims[fuzz_input.blueprints[nonego_idx]]['length']
    offset = self.random.uniform(car_length, max_dist)

    # Mutate
    mutant = self.copy_forward_with_params(fuzz_input, nonego_idx, offset)
    mutant = self.remove_vehicle_with_params(mutant, nonego_idx)

    print(f'Mutation: Moved nonego {nonego_idx} forward along its route by {offset} meters.')

    return mutant
  
  def copy_forward_with_params(self, fuzz_input, nonego_idx, offset):
    # Move the trajectory, extend the route if necessary
    network = StructureAwareMutator.get_network(fuzz_input)
    lanes = [network.elements[lane_id]
             for lane_id in fuzz_input.routes[nonego_idx]]
    centerline = shapely.geometry.MultiLineString([l.centerline.points for l in lanes])
    footprint = fuzz_input.footprints[nonego_idx]
    available = centerline.length - footprint.ctrlpts[-1][0]
    if offset > available - 10: # 10 meters cushion
      # Extend the route by offset-available+10
      ext = self._extend_lanes_forward(lanes, offset-available+10)
      lanes += ext
      print(f'Extended the route forward by {sum(l.centerline.length for l in ext)} meters.')

    start_lane_idx = 0
    trim_length = 0
    while footprint.ctrlpts[0][0]+offset-trim_length > lanes[start_lane_idx].centerline.length:
      trim_length += lanes[start_lane_idx].centerline.length
      start_lane_idx += 1   
    new_route = tuple(l.uid for l in lanes[start_lane_idx:])
    if trim_length > 0:
      print(f'Trimmed {trim_length} meters from the beginning of the route.')

    new_footprint =  Spline(degree=footprint.degree,
                           ctrlpts=tuple((p[0]+offset-trim_length, p[1]) for p in footprint.ctrlpts),
                           knotvector=footprint.knotvector)

    mutant = FuzzInput(config=fuzz_input.config,
                  blueprints=fuzz_input.blueprints+(fuzz_input.blueprints[nonego_idx],),
                  routes=fuzz_input.routes+(new_route,),
                  footprints=fuzz_input.footprints+(new_footprint,),
                  timings=fuzz_input.timings+(fuzz_input.timings[nonego_idx],),
                  signals=fuzz_input.signals+(fuzz_input.signals[nonego_idx],)
                  )
    return mutant
    
  def copy_forward(self, fuzz_input):
    """Copy a trajectory and add some longitudinal offset along the route.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))
    max_dist = 100
    car_length = self.blueprint2dims[fuzz_input.blueprints[nonego_idx]]['length']
    offset = self.random.uniform(car_length, max_dist)

    # Mutate
    mutant = self.copy_forward_with_params(fuzz_input, nonego_idx, offset)

    print(f'Mutation: Copied nonego {nonego_idx} forward by {offset} meters.')

    return mutant
  
  def move_backward(self, fuzz_input):
    """Subtracts some longitudinal offset from a trajectory along its route.
    Extends the route backwards randomly, if necessay.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))
    max_dist = 100 # bigger than any vehicle length
    car_length = self.blueprint2dims[fuzz_input.blueprints[nonego_idx]]['length']
    offset = self.random.uniform(car_length, max_dist)

    # Mutate
    mutant = self.copy_backward_with_params(fuzz_input, nonego_idx, offset)
    mutant = self.remove_vehicle_with_params(mutant, nonego_idx)

    print(f'Mutation: Moved nonego {nonego_idx} backwards by {offset} meters.')

    return mutant

  def copy_backward_with_params(self, fuzz_input, nonego_idx, offset):
    lanes = [self.get_network(fuzz_input).elements[lane_id]
             for lane_id in fuzz_input.routes[nonego_idx]]
    footprint = fuzz_input.footprints[nonego_idx]
    available = footprint.ctrlpts[0][0]
    ext_len = 0
    if offset > available - 10: # 10 meters cushion
      # Extend the route by offset-available+10
      ext = self._extend_lanes_backward(fuzz_input.config['carla-map'], lanes, offset-available+10)
      ext_len = sum(l.centerline.length for l in ext)
      lanes =  ext + lanes
      print(f'Extended the route backwards by {ext_len} meters.')
    
    new_footprint = Spline(degree=footprint.degree,
                      ctrlpts=tuple((p[0]+ext_len-offset, p[1]) for p in footprint.ctrlpts),
                      knotvector=footprint.knotvector)
    new_route = tuple(l.uid for l in lanes)

    mutant = FuzzInput(config=fuzz_input.config,
                  blueprints=fuzz_input.blueprints+(fuzz_input.blueprints[nonego_idx],),                       
                  routes=fuzz_input.routes+(new_route,),
                  footprints=fuzz_input.footprints+(new_footprint,),
                  timings=fuzz_input.timings+(fuzz_input.timings[nonego_idx],),
                  signals=fuzz_input.signals+(fuzz_input.signals[nonego_idx],)
                  )
    return mutant
  
  def copy_backward(self, fuzz_input):
    """Copy a trajectory and add some longitudinal offset along the route.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))
    max_dist = 100 # bigger than any vehicle length
    car_length = self.blueprint2dims[fuzz_input.blueprints[nonego_idx]]['length']
    offset = self.random.uniform(car_length, max_dist)

    # Mutate
    mutant = self.copy_backward_with_params(fuzz_input, nonego_idx, offset)

    print(f'Mutation: Copied nonego {nonego_idx} backwards by {offset} meters.')

    return mutant
  
  def change_route(self, fuzz_input):
    """Move a trajectory to a different route.
    The local curvilinear coordinates of the control points are preserved.
    """
    # Choose a random vehicle and calculate its trajectory length
    nonego_idx = self.random.randrange(len(fuzz_input.routes))

    # Choose a random maneuver through the intersection
    network = self.get_network(fuzz_input)
    intersection = network.elements[fuzz_input.config['intersection']]
    maneuver = self.random.choice(intersection.maneuvers)
    
    mutant = self.copy_to_route_with_params(fuzz_input, nonego_idx, maneuver)
    mutant = self.remove_vehicle_with_params(mutant, nonego_idx)

    print(f'Mutation: Moved nonego {nonego_idx} to route {maneuver.startLane.uid, maneuver.connectingLane.uid, maneuver.endLane.uid}.')

    return mutant
  
  def copy_to_route_with_params(self, fuzz_input, nonego_idx, maneuver):
    network = self.get_network(fuzz_input)
    old_route = fuzz_input.routes[nonego_idx]
    old_lanes = [network.elements[uid] for uid in old_route]
    old_route_len = sum((l.centerline.length for l in old_lanes))
    
    lanes = [maneuver.startLane, maneuver.connectingLane, maneuver.endLane]
    route_len = sum((l.centerline.length for l in lanes))
    if old_route_len > route_len:
      lanes += self._extend_lanes_forward(lanes, old_route_len - route_len)

    route = tuple(l.uid for l in lanes)

    mutant = FuzzInput(config=fuzz_input.config,
                  blueprints=fuzz_input.blueprints+(fuzz_input.blueprints[nonego_idx],),
                  routes=fuzz_input.routes+(route,),
                  footprints=fuzz_input.footprints+(fuzz_input.footprints[nonego_idx],),
                  timings=fuzz_input.timings+(fuzz_input.timings[nonego_idx],),
                  signals=fuzz_input.signals+(fuzz_input.signals[nonego_idx],)
                  )
    
    return mutant

  def copy_to_route(self, fuzz_input):
    """Copy a trajectory to a different route.
    """
    # Choose random parameters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))  
    network = self.get_network(fuzz_input)
    intersection = network.elements[fuzz_input.config['intersection']]
    maneuver = self.random.choice(intersection.maneuvers)

    # Mutate
    mutant = self.copy_to_route_with_params(fuzz_input, nonego_idx, maneuver)
    
    print(f'Mutation: Copied nonego {nonego_idx} to route {maneuver.startLane.uid, maneuver.connectingLane.uid, maneuver.endLane.uid}')

    return mutant

  def remove_vehicle_with_params(self, fuzz_input, nonego_idx):
    mutant = FuzzInput(config=fuzz_input.config,
                  blueprints=fuzz_input.blueprints[0:nonego_idx]+fuzz_input.blueprints[nonego_idx+1:],
                  routes=fuzz_input.routes[0:nonego_idx]+fuzz_input.routes[nonego_idx+1:],
                  footprints=fuzz_input.footprints[0:nonego_idx]+fuzz_input.footprints[nonego_idx+1:],
                  timings=fuzz_input.timings[0:nonego_idx]+fuzz_input.timings[nonego_idx+1:],                  
                  signals=fuzz_input.signals[0:nonego_idx]+fuzz_input.signals[nonego_idx+1:]
                  )
    return mutant
  
  def remove_vehicle(self, fuzz_input):
    """Removes a random non-ego from the scenario.
    """
    if len(fuzz_input.routes) == 1:
      raise MutationError('Cannot remove the singleton nonego, empty scenarios are not allowed!')
    
    # Choose random parameters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))

    # Mutate
    mutant = self.remove_vehicle_with_params(fuzz_input, nonego_idx)
    
    print(f'Mutation: Removed nonego {nonego_idx} from the fuzz_input.')

    return mutant

  def speedup_with_params(self, fuzz_input, nonego_idx, interval, factor):
    timing = fuzz_input.timings[nonego_idx]

    spline = BSpline.Curve(normalize_kv = False)
    spline.degree = timing.degree
    spline.ctrlpts = copy.deepcopy(timing.ctrlpts) # fuzz_input should not be mutated
    spline.knotvector = timing.knotvector

    # Move the corresponding controlpoints vertically up
    d_min = geomdl.operations.find_ctrlpts(spline, interval[0])[-1][1]
    d_max = geomdl.operations.find_ctrlpts(spline, interval[1])[0][1]
    interval_ctrlpts = tuple(p for p in spline.ctrlpts if p[1] >= d_min and p[1] <= d_max)
    for pi, pii in zip(reversed(interval_ctrlpts[:-1]), reversed(interval_ctrlpts[1:])):
      pi[1] = (1-factor)*pi[1] + factor*pii[1]

    # Construct the new fuzz_input
    timing_mutated = Spline(degree=timing.degree,
                              ctrlpts=tuple(tuple(ctrlpt) for ctrlpt in spline.ctrlpts),
                              knotvector=tuple(spline.knotvector)
                              )
    
    mutant = FuzzInput(config=fuzz_input.config,
                  blueprints=fuzz_input.blueprints,
                  routes=fuzz_input.routes,
                  footprints=fuzz_input.footprints,
                  timings=
                    fuzz_input.timings[0:nonego_idx] \
                    + (timing_mutated,) \
                    + fuzz_input.timings[nonego_idx+1:],
                  signals=fuzz_input.signals
                  )
  
    return mutant

  def speedup(self, fuzz_input):
    """Speeds up a random nonego over a random time interval [a, b].
    """
    # Choose random paramters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))
    timing = fuzz_input.timings[nonego_idx]
    a = self.random.uniform(0, timing.ctrlpts[-1][1])
    b = self.random.uniform(a, timing.ctrlpts[-1][1])
    factor = self.random.uniform(.1, .9)
    
    # Mutate
    mutant = self.speedup_with_params(fuzz_input, nonego_idx, (a, b), factor)

    print(f'Speed up nonego {nonego_idx} over interval {(a, b)} by a factor of {factor}.')

    return mutant

  def slowdown_with_params(self, fuzz_input, nonego_idx, interval, factor):
    timing = fuzz_input.timings[nonego_idx]

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

    # Construct the new fuzz_input
    timing_mutated = Spline(degree=timing.degree,
                            ctrlpts=tuple(tuple(ctrlpt) for ctrlpt in spline.ctrlpts),
                            knotvector=tuple(spline.knotvector)
                            )

    mutant = FuzzInput(config=fuzz_input.config,
                  blueprints=fuzz_input.blueprints,
                  routes=fuzz_input.routes,
                  footprints=fuzz_input.footprints,
                  timings=
                    fuzz_input.timings[0:nonego_idx] \
                    + (timing_mutated,) \
                    + fuzz_input.timings[nonego_idx+1:],
                  signals=fuzz_input.signals
                  )
  
    return mutant
  
  def slowdown(self, fuzz_input):
    # Choose random parameters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))
    timing = fuzz_input.timings[nonego_idx]
    a = self.random.uniform(0, timing.ctrlpts[-1][1])
    b = self.random.uniform(a, timing.ctrlpts[-1][1])
    factor = self.random.uniform(.1, .9)

    # Mutate
    mutant = self.slowdown_with_params(fuzz_input, nonego_idx, (a, b), factor)

    print(f'Mutation: Slowed down nonego {nonego_idx} over interval {(a, b)} by a factor of {factor}.')

    return mutant
  
  def add_signal(self, fuzz_input):
    # Choose random parameters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))
    timing = fuzz_input.timings[nonego_idx]
    t = self.random.uniform(0, timing.knotvector[-1])
    signal = self.random.choice(tuple(SignalType))
    
    # Mutate
    print(f'Mutation: Nonego {nonego_idx} signals {signal} at time {t}.')
    mutant = self.add_signal_with_params(fuzz_input, nonego_idx, t, signal)

    return mutant
  
  def add_signal_with_params(self, fuzz_input, nonego_idx, event_time, new_signal):
    signal = fuzz_input.signals[nonego_idx]
    t2s = {t:s for t,s in signal}
    t2s[event_time] = new_signal    
    signal = sorted(t2s.items(), key=lambda p: p[0])

    mutant = FuzzInput(config=fuzz_input.config,
                  blueprints=fuzz_input.blueprints+(fuzz_input.blueprints[nonego_idx],),
                  routes=fuzz_input.routes+(fuzz_input.routes[nonego_idx],),
                  footprints=fuzz_input.footprints+(fuzz_input.footprints[nonego_idx],),
                  timings=fuzz_input.timings+(fuzz_input.timings[nonego_idx],),
                  signals=fuzz_input.signals+(tuple(signal),)
                  )
    mutant = self.remove_vehicle_with_params(mutant, nonego_idx)

    return mutant
  
  def remove_signal(self, fuzz_input):
    # Choose random parameters
    nonego_idx = self.random.randrange(len(fuzz_input.routes))
    signal = fuzz_input.signals[nonego_idx]

    if len(signal) == 1:
      raise MutationError("Cannot remove a nonegos's initial signal!")   

    event_index = self.random.randrange(1, len(signal))

    print(f'Mutation: Nonego {nonego_idx} will not signal at time {signal[event_index][0]}.')
    mutant = self.remove_signal_with_params(fuzz_input, nonego_idx, event_index)

    return mutant
  
  def remove_signal_with_params(self, fuzz_input, nonego_idx, event_index):
    signal = fuzz_input.signals[nonego_idx]
    mutant = FuzzInput(config=fuzz_input.config,
                  blueprints=fuzz_input.blueprints + (fuzz_input.blueprints[nonego_idx],),
                  routes=fuzz_input.routes + (fuzz_input.routes[nonego_idx],),
                  footprints=fuzz_input.footprints + (fuzz_input.footprints[nonego_idx],),
                  timings=fuzz_input.timings + (fuzz_input.timings[nonego_idx],),
                  signals=fuzz_input.signals + (signal[:event_index] + signal[event_index+1:],)
                  )
    mutant = self.remove_vehicle_with_params(mutant, nonego_idx)

    return mutant
  
  def mutate_ego_route(self, fuzz_input):
    """Change VUT's initial state or expected route."""
    # Choose a random maneuver through the intersection
    network = self.get_network(fuzz_input)
    intersection = network.elements[fuzz_input.config['intersection']]
    lanes = [self.random.choice(intersection.incomingLanes)]
    if lanes[0].centerline.length < self.min_ego_distance_to_intersection:
      print('Incoming lane is too short, need to extend it backwards...')
      lanes = extend_lane_backward(lanes[0], self.min_ego_distance_to_intersection - lanes[0].centerline.length, self.random)\
              + lanes
    route_length = sum(l.centerline.length for l in lanes)
    x0 = self.random.uniform(1, route_length - self.min_ego_distance_to_intersection)
    if route_length - x0 < self.min_route_length:
      lanes.extend(extend_lane_forward(lanes[-1], self.min_route_length-route_length+x0, self.random))
    route = tuple(l.uid for l in lanes)
    init_progress_ratio = x0 / sum(l.centerline.length for l in lanes)
    
    mutant = FuzzInput(config={**fuzz_input.config,
                               'ego_route': route,
                               'ego_init_progress_ratio': init_progress_ratio
                              },
                       blueprints=fuzz_input.blueprints,
                       routes=fuzz_input.routes,
                       footprints=fuzz_input.footprints,
                       timings=fuzz_input.timings,
                       signals=fuzz_input.signals
                       )

    print(f'Mutation: Ego route is now {route} with initial progress ratio {init_progress_ratio}.')

    return mutant 

  def mutate(self, fuzz_input):
    mutator = self.random.choice(self.mutators)
    try:
      mutant = mutator(fuzz_input)
    except MutationError as err:
      print('Mutation failed: ' + err.msg)
      return fuzz_input
    except Exception as e:
      print(f'Error in the mutator: {e}')
      bug = {
        'fuzz-input': fuzz_input,
        'mutator': mutator,
        'exception': e,
      }
      bug_bytes = jsonpickle.encode(bug, indent=1).encode('utf-8')
      bug_hash = hashlib.sha1(bug_bytes).hexdigest()
      with open(f'mutator-bug_{bug_hash}.json', 'wb') as f:
        f.write(bug_bytes)
      raise e
    else:
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
    """Exception raised for errors in mutating a fuzz_input.
    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.msg = message