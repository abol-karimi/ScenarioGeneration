# External libraries
import numpy as np
import random
import carla

# This project
from scenariogen.core.utils import sample_spline


def draw_lane(world, lane,
              boundaries=True,
              centerlines=False,
              label=True,
              boundary_color=carla.Color(255, 0, 0),
              centerline_color=carla.Color(0, 255, 0),
              life_time=-1, 
              height=0.2):

    if boundaries:
    # Draw lane boundaries
        locations = [carla.Location(p[0], -p[1], height)
                    for p in lane.leftEdge.lineString.coords]
        for i in range(len(locations)-1):
            begin = locations[i]
            end = locations[i+1]
            world.debug.draw_line(
                begin, end, thickness=0.1, color=boundary_color, life_time=life_time)
        locations = [carla.Location(p[0], -p[1], height)
                    for p in lane.rightEdge.lineString.coords]
        for i in range(len(locations)-1):
            begin = locations[i]
            end = locations[i+1]
            world.debug.draw_line(
                begin, end, thickness=0.1, color=boundary_color, life_time=life_time)
    if centerlines:
        locations = [carla.Location(p[0], -p[1], height)
                    for p in lane.centerline.lineString.coords]
        for i in range(len(locations)-1):
            begin = locations[i]
            end = locations[i+1]
            world.debug.draw_line(
                begin, end, thickness=0.05, color=centerline_color, life_time=life_time)        
    if label:
    # Draw lane label
        ds = list(np.arange(random.uniform(1, 2), lane.centerline.length-random.uniform(1, 2), random.uniform(6, 8)))
        ps = [lane.centerline.pointAlongBy(d)
              for d in ds]
        locs = [carla.Location(p.x, -p.y, 0.5)
                for p in ps]
        for loc in locs:
            world.debug.draw_string(loc, lane.uid, life_time=1000)


def draw_intersection(world, intersection, 
                      draw_lanes=False,
                      label_lanes=False,
                      draw_crossings=False,
                      arrival_distance=4, 
                      height=0.1,
                      life_time=-1
                      ):
    # Boundaries of the intersection
    locs = [carla.Location(p[0], -p[1], height)
            for p in intersection.polygon.exterior.coords]
    for i in range(len(locs)):
        p0 = locs[i]
        p1 = locs[(i+1) % len(locs)]
        world.debug.draw_line(
            p0, p1, color=carla.Color(0, 0, 255), life_time=0)
    
    # Pedestrian crossings
    for cross in intersection.crossings:
        locs = [carla.Location(p[0], -p[1], height)
                for p in cross.polygon.exterior.coords]
        for i in range(len(locs)):
            p0 = locs[i]
            p1 = locs[(i+1) % len(locs)]
            world.debug.draw_line(
                p0, p1, color=carla.Color(0, 255, 0), life_time=0)


    # Draw arrival boxes
    for lane in intersection.incomingLanes:
        l = lane.leftEdge[-1]
        vl = lane.flowFrom(l, -arrival_distance)
        r = lane.rightEdge[-1]
        vr = lane.flowFrom(r, -arrival_distance)
        loc_l = carla.Location(vl.x, -vl.y, height)
        loc_r = carla.Location(vr.x, -vr.y, height)
        world.debug.draw_line(
            loc_l, loc_r, thickness=0.1, life_time=1000)

    if label_lanes:
    # Draw lane names
        for lane in intersection.incomingLanes + intersection.outgoingLanes:
            draw_lane(world, lane, life_time=life_time, label=label_lanes)

    elif draw_lanes:
    # Draw connecting lanes
        for m in intersection.maneuvers:
            l = m.connectingLane
            draw_lane(world, l, height=height)

def set_camera(world, intersection, height=30):
    centroid = intersection.polygon.centroid  # a Shapely point
    loc = carla.Location(centroid.x, -centroid.y, height)
    rot = carla.Rotation(pitch=-90)
    world.get_spectator().set_transform(carla.Transform(loc, rot))

def label_car(world, car):
    loc = carla.Location(car.position.x, -car.position.y, 1.5)
    world.debug.draw_string(loc, car.name, life_time=0.01)


def draw_trajectories(world, sim_trajectory):
    for states in sim_trajectory:
        for state in states.values():
            position = state[0]
            loc = carla.Location(position.x, -position.y, 0.1)
            world.debug.draw_point(loc)

def draw_point(world, point, height=None, size=0.1,
               color=carla.Color(255, 0, 0),
               lifetime=-1.0):
        """The point can be either a list or a Point object,
        with Scenic's coordinates.
        """
        if isinstance(point, list) or isinstance(point, tuple):
            x, y = point[0], -point[1]
            z = height if (not height is None) else point[2]
        else:
            x, y = point.x, -point.y
            z = height if (not height is None) else point.z
        loc = carla.Location(x, y, z)
        world.debug.draw_point(loc, size, color, lifetime)

def draw_rect(world, rect, height=0.1):
    corners = [carla.Location(p.x, -p.y, height) for p in rect.corners]
    for i in range(-1, len(corners)-1):
        world.debug.draw_line(corners[i], corners[i+1])

def draw_spline(world, spline, resolution, interval,
                size=0.1,
                color=carla.Color(255, 0, 0),
                lifetime=-1.0):
    steps = int(interval[1] // resolution)
    spline_sample = sample_spline(spline,
                                steps+1,
                                interval[0], 
                                interval[1])
    for i, p in enumerate(spline_sample):
        draw_point(world,
                   p[0:2], 
                   p[2],
                   size,
                   color,
                   lifetime)
