import geomdl
from geomdl import BSpline
import numpy as np
import scipy

from scenic.core.object_types import OrientedPoint
from scenic.core.vectors import Vector
from scenic.core.geometry import headingOfSegment

# This project
from scenariogen.core.fuzz_input import FuzzInput, Spline
from scenariogen.core.signals import SignalType
from scenariogen.core.geometry import CurvilinearTransform

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
        signal = SignalType.from_maneuver(maneuver).name.lower()
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
    for sim_traj, transform in zip(sim_trajs, sim_result.records['transforms']):
        xs = [sim_traj[0][0]]
        ys = [sim_traj[0][1]]
        ts = [sim_traj[0][2]]
        ds = [0]
        v1 = Vector(xs[-1], ys[-1])
        for i in range(1, len(sim_traj)):
            v2 = Vector(sim_traj[i][0], sim_traj[i][1])
            dv = v2 - v1
            if dv[0] != 0 and dv[1] != 0:
                xs.append(sim_traj[i][0])
                ys.append(sim_traj[i][1])
                ts.append(sim_traj[i][2])
                ds.append(ds[-1] + dv.norm())
                v1 = Vector(xs[-1], ys[-1])
        
        knotvector = [ds[0]]*degree \
                    + list(np.linspace(ds[0], ds[-1], knots_size)) \
                    + [ds[-1]]*degree 
        tck, _ = scipy.interpolate.splprep([xs, ys], # curve samples
                                        u=ds, # parameterize by travelled distance
                                        k=degree,
                                        task=-1, # spline approximation
                                        t=knotvector
                                        )
        # Transform control points to curvilinear coordinates
        footprint = Spline(degree=degree,
                        ctrlpts=tuple(transform.curvilinear((x, y))
                                        for x,y in zip(tck[1][0], tck[1][1])),
                        knotvector=tuple(float(knot) for knot in tck[0])
                        )
        
        knotvector = [ts[0]]*degree \
                    + list(np.linspace(ts[0], ts[-1], knots_size)) \
                    + [ts[-1]]*degree # knotvector
        tck, _ = scipy.interpolate.splprep([ts, ds], # curve samples
                                        u=ts, # curve parameters corresponding to the samples
                                        k=degree, 
                                        task=-1, # spline approximation
                                        t=knotvector
                                        )
        timing = Spline(degree=degree,
                    ctrlpts=tuple((float(x),float(y))
                                    for x,y in zip(tck[1][0], tck[1][1])),
                    knotvector=tuple(float(knot) for knot in tck[0])
                    )
        footprints.append(footprint)
        timings.append(timing)
      
    return FuzzInput(config=sim_result.records['config'],
                     routes=sim_result.records['routes'],
                     footprints=tuple(footprints),
                     timings=tuple(timings),
                     signals=sim_result.records['signals'],
                     lengths=sim_result.records['lengths'],
                     widths=sim_result.records['widths'])

def sample_trajectories(network, seed, sample_size, umin=0, umax=None):
    if umax is None:
        umax = seed.timings[0].ctrlpts[-1][0]
    trajectories = []
    ts = np.linspace(umin, umax, num=sample_size)
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

def classify_intersection(intersection):
    return

def connecting_lane(network, start, end):
    for m in network.elements[start].maneuvers:
        if m.endLane.uid == end:
            return m.connectingLane.uid

def is_collision_free(objects):
  pairs = [(objects[i], objects[j]) 
           for i in range(len(objects)) 
           for j in range(i+1, len(objects))]
  for c, d in pairs:
    if c.intersects(d):
      return False
  return True

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
        manuevers = tuple(filter(lambda i: i.type == turn, current_lane.maneuvers))
        if len(manuevers) == 0:
            print('The expected turn not available at the junction!')
            exit()
        current_lane = manuevers[0].connectingLane
        route.append(current_lane.uid)
    while not current_lane.maneuvers[0].intersection:
        route.append(current_lane.successor.uid)
        current_lane = current_lane.successor
    return route
