from itertools import product, chain
from more_itertools import pairwise
from cachetools import cached
from cachetools.keys import hashkey
import geomdl
from geomdl import BSpline
import numpy as np
import sympy
from scipy.interpolate import splprep, splev
import matplotlib.pyplot as plt

from scenic.core.object_types import OrientedPoint
from scenic.core.vectors import Vector
from scenic.core.geometry import headingOfSegment
from scenic.domains.driving.roads import ManeuverType

# This project
from scenariogen.core.fuzz_input import FuzzInput, Spline
from scenariogen.core.signals import SignalType
from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.core.errors import SplineApproximationError

def route_length(route):
  return sum([l.centerline.length for l in route])

def geometry_atoms(network, intersection_uid):
    intersection = network.elements[intersection_uid]
    maneuvers = intersection.maneuvers
    geometry = []
    for maneuver in maneuvers:
        lane = maneuver.connectingLane
        fork = maneuver.startLane
        exit = maneuver.endLane
        geometry.append(
            f'laneFromTo({lane.uid}, {fork.uid}, {exit.uid})')

    for maneuver in maneuvers:
        lane = maneuver.connectingLane
        signal = SignalType.from_maneuver_type(maneuver.type).name.lower()
        geometry.append(
            f'laneCorrectSignal({lane.uid}, {signal})')

    for i in range(len(maneuvers)):
        li = maneuvers[i].connectingLane
        geometry.append(f'overlaps({li.uid}, {li.uid})')
        for j in range(i+1, len(maneuvers)):
            lj = maneuvers[j].connectingLane
            if li.intersects(lj):
                geometry.append(f'overlaps({li.uid}, {lj.uid})')
                geometry.append(f'overlaps({lj.uid}, {li.uid})')

    roads = intersection.roads
    incomings = intersection.incomingLanes
    road2incomings = {road.uid: [] for road in roads}
    for incoming in incomings:
        road2incomings[incoming.road.uid].append(incoming.uid)
    # An intersection stores the intersecting roads in CW or CCW order.
    # Assuming the order is CCW, then:
    import math
    for i in range(len(roads)):
        ii = (i+1) % len(roads)  # cyclic order
        lefts = road2incomings[roads[i].uid]
        rights = road2incomings[roads[ii].uid]
        l0 = network.elements[lefts[0]]
        r0 = network.elements[rights[0]]
        hl = l0.centerline[-1] - l0.centerline[-2]  # heading
        hr = r0.centerline[-1] - r0.centerline[-2]  # heading
        # Ignore roads on opposing directions:
        if abs(math.pi - abs(hr.angleWith(hl))) < math.pi/6:
            continue
        geometry += [
            f'isOnRightOf({right}, {left})' for left in lefts for right in rights]
    
    # Patching Scenic's geometry model
    if intersection_uid == 'intersection1930':
        for lane in intersection.incomingLanes:
            geometry.append(f'hasStopSign({lane.uid})')
            
    return geometry

def sim_trajectories(sim_result, timestep):
    cars_num = len(sim_result.records['poses'][0])
    sim_trajs = [[] for k in range(cars_num)]
    for i, poses in enumerate(sim_result.records['poses']):
        time = i * timestep
        for j, ((x, y), heading) in enumerate(poses):
            p = Vector(x, y)
            pose = OrientedPoint(position=p, heading=heading)
            sim_trajs[j].append((pose, time))
    return sim_trajs

def seed_from_sim(sim_result, timestep, degree=3, knots_size=20):
    cars_num = len(sim_result.records['routes'])
    sim_trajs = [[] for k in range(cars_num)]
    for i, footprints in sim_result.records['footprints']:
        for j, p in enumerate(footprints):
            sim_trajs[j].append((p[0], p[1], i*timestep))
    
    footprints = []
    timings = []
    for name, sim_traj, transform in zip(sim_result.records['names'],
                                         sim_trajs,
                                         sim_result.records['transforms']):
        ds = [0]
        for i in range(0, len(sim_traj)-1):
            dv = Vector(sim_traj[i+1][0], sim_traj[i+1][1]) \
                - Vector(sim_traj[i][0], sim_traj[i][1])
            ds.append(ds[-1] + dv.norm())
        xs = [p[0] for p,(d1,d2) in zip(sim_traj, pairwise([-1, *ds])) if d1 < d2]
        ys = [p[1] for p,(d1,d2) in zip(sim_traj, pairwise([-1, *ds])) if d1 < d2]
        ds_increasing = [d2 for d1,d2 in pairwise([-1, *ds]) if d1 < d2]

        try:
            ((t, c, k), u), fp, ier, msg = splprep([xs, ys], # curve samples
                                        u=ds_increasing, # parameterize by travelled distance
                                        k=degree,
                                        task=0, # spline approximation with smoothing
                                        s=.1, # Larger s means more smoothing
                                        full_output=1
                                       )
            print(f'Then footprint spline for car {name} has {len(t)} knots.')
            print(f'The weighted sum of squared residuals of the spline approximation for footprint: {fp}')
            print(f'ier: {ier}, msg: {msg}')
        except Exception as e:
            raise SplineApproximationError(f'SplineApproximationError when approximating the footprint for car {name}: {e}')
        
       
        # Transform control points to curvilinear coordinates
        footprint = Spline(degree=degree,
                           ctrlpts=tuple(transform.curvilinear((x, y))
                                           for x,y in zip(c[0], c[1])),
                           knotvector=tuple(float(knot) for knot in t)
                          )
        fig, axs = plt.subplots(2)
        fig.suptitle(f'Car {name}')
        axs[0].set_title('xy-plain')
        axs[0].plot(xs, ys, 'go')
        sample = splev(ds_increasing, (t, c, k))
        axs[0].plot(sample[0], sample[1], 'r-')

        ts = [p[2] for p in sim_traj]

        try:
            ((t, c, k), u), fp, ier, msg = splprep([ts, ds], # curve samples
                                                   u=ts, # curve parameters corresponding to the samples
                                                   k=degree, 
                                                   task=0, # spline approximation with smoothing
                                                   s=.1, # Larger s means more smoothing
                                                   full_output=1
                                                  )
            print(f'Then timing spline for car {name} has {len(t)} knots.')
            print(f'The weighted sum of squared residuals of the spline approximation for timing: {fp}')
            print(f'ier: {ier}, msg: {msg}')
        except Exception as e:
            raise SplineApproximationError(f'SplineApproximationError when approximating the timing for car {name}: {e}')
        
        timing = Spline(degree=degree,
                        ctrlpts=tuple((float(x),float(y))
                                        for x,y in zip(c[0], c[1])),
                        knotvector=tuple(float(knot) for knot in t)
                       )
        axs[1].set_title('td-plain')
        axs[1].plot(ts, ds, 'go')
        sample = splev(ts, (t, c, k))
        axs[1].plot(sample[0], sample[1], 'r-')
        plt.show()

        footprints.append(footprint)
        timings.append(timing)

    sim_signals = [[] for k in range(cars_num)]
    for i, signals in sim_result.records['signals']:
        for j, s in enumerate(signals):
            sim_signals[j].append((i*timestep, s))
    signals = []
    for sim_signal in sim_signals:
        events = (sim_signal[0],) + tuple((tii,sii) for (ti,si),(tii,sii) in pairwise(sim_signal) if sii != si)
        t_events = (e[0] for e in events)
        s_events = (e[1] for e in events)

        spline = BSpline.Curve(normalize_kv = False)
        spline.degree = timing.degree
        spline.ctrlpts = timing.ctrlpts
        spline.knotvector = timing.knotvector
        d_events = tuple(t_d[1] for t_d in spline.evaluate_list(t_events))

        signals.append(tuple(zip(d_events, s_events)))
    
    return FuzzInput(config=sim_result.records['config'],
                    blueprints=sim_result.records['blueprints'],
                    routes=sim_result.records['routes'],
                    footprints=tuple(footprints),
                    timings=tuple(timings),
                    signals=tuple(signals))

def sample_trajectories(network, seed, sample_size):
    trajectories = []
    ts = np.linspace(0, seed.timings[0].knotvector[-1], num=sample_size)
    for route, footprint, timing in zip(seed.routes, seed.footprints, seed.timings):
        axis_coords = [p for uid in route for p in network.elements[uid].centerline.lineString.coords]
        transform = CurvilinearTransform(axis_coords)
        footprint_rectilinear = Spline(degree=footprint.degree,
                                      ctrlpts=tuple(transform.rectilinear(p) for p in footprint.ctrlpts),
                                      knotvector=footprint.knotvector)
        trajectories.append(sample_trajectory(footprint_rectilinear, timing, ts))

    return trajectories

def sample_trajectory(footprint, timing, ts):
    spline = BSpline.Curve(normalize_kv = False)
    spline.degree = timing.degree
    spline.ctrlpts = timing.ctrlpts
    spline.knotvector = timing.knotvector
    ds = tuple(t_d[1] for t_d in spline.evaluate_list(ts))

    # Plug the timing output into the footprint input
    spline.degree = footprint.degree
    spline.ctrlpts = footprint.ctrlpts
    spline.knotvector = footprint.knotvector
    sample = geomdl.operations.tangent(spline, ds)
    return tuple((s[0][0], # x
                  s[0][1], # y
                  headingOfSegment((0, 0), (s[1][0], s[1][1])), # heading
                  )
                  for s in sample)

def sample_signal_actions(seed, sample_size):
    signals_actions = []
    ts = np.linspace(0, seed.timings[0].knotvector[-1], num=sample_size)
    for timing, signal in zip(seed.timings, seed.signals):
        spline = BSpline.Curve(normalize_kv = False)
        spline.degree = timing.degree
        spline.ctrlpts = timing.ctrlpts
        spline.knotvector = timing.knotvector
        ds = tuple(max(t_d[1], 0) for t_d in spline.evaluate_list(ts))
        x = sympy.Symbol('x', real=True)
        pieces = tuple(chain(((s.value, x >= d) for d,s in reversed(signal)),
                             ((SignalType.OFF.value, x >= 0),)
                            )
                      )
        d2s = sympy.Piecewise(*pieces)
        signals = tuple(d2s.subs(x, d) for d in ds)
        signal_actions = tuple(SignalType(sii) if si != sii else None for si,sii in pairwise(signals))
        signals_actions.append(signal_actions)

    return signals_actions

def classify_intersection(intersection):
    return

def connecting_lane(network, start, end):
    for m in network.elements[start].maneuvers:
        if m.endLane.uid == end:
            return m.connectingLane.uid

def collides_with(query, data):
    for q, d in product(query, data):
        if q.intersects(d):
            return True
    return False

def route_from_turns(network, init_lane, turns):
    """
    init_lane: the first lane in the mission
    turns: a tuple of turning directions of the route at each intersection
    
    Returns a tuple of lanes.
    """
    route = [init_lane]
    current_lane = network.elements[init_lane]
    for turn in turns:
        while not current_lane.maneuvers[0].intersection:
            route.append(current_lane.successor.uid)
            current_lane = current_lane.successor
        manuevers = tuple(filter(lambda m: m.type == turn, current_lane.maneuvers))
        if len(manuevers) == 0:
            print('The expected turn not available at the intersection!')
            exit(1)
        current_lane = manuevers[0].connectingLane
        route.append(current_lane.uid)
    while not current_lane.maneuvers[0].intersection:
        route.append(current_lane.successor.uid)
        current_lane = current_lane.successor
    return route

def extend_lane_forward(lane, length, random):
    maneuver = random.choice(lane.maneuvers)
    ext = [maneuver.connectingLane if maneuver.connectingLane else maneuver.endLane]
    ext_len = ext[-1].centerline.length
    while ext_len < length:
        maneuver = random.choice(ext[-1].maneuvers)
        ext.append(maneuver.connectingLane if maneuver.connectingLane else maneuver.endLane)
        ext_len += ext[-1].centerline.length
    return ext

@cached(cache={}, key=lambda network: hashkey(tuple(i.uid for i in network.intersections)))
def lane_to_predecessors(network):
    lane2predecessors = {lane:[] for lane in network.lanes}
    for lane in network.lanes:
        if not lane.predecessor is None:
            lane2predecessors[lane].append(lane.predecessor)
    for intersection in network.intersections:
        for maneuver in intersection.maneuvers:
            lane2predecessors[maneuver.endLane].append(maneuver.connectingLane)
    return lane2predecessors


def extend_lane_backward(lane, length, random):
    print(f'Extending lane {lane.uid} backwards...')
    lane2predecessors = lane_to_predecessors(lane.network)
    print('lane2pred calculated!')
    ext = [random.choice(lane2predecessors[lane])]
    ext_len = ext[-1].centerline.length
    while ext_len < length:
      ext.append(random.choice(lane2predecessors[ext[-1]]))
      ext_len += ext[-1].centerline.length
    ext.reverse()
    return ext

def signal_from_lanes(lanes):
    signal = []
    for i in range(len(lanes)-2):
        dist = sum(lanes[j].centerline.length for j in range(i))
        maneuver_type = ManeuverType.guessTypeFromLanes(lanes[i], lanes[i+2], lanes[i+1])
        sig = SignalType.from_maneuver_type(maneuver_type)
        signal.append((dist, sig))

    return tuple(signal)