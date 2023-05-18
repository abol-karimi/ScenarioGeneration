import carla
from scenic.core.geometry import _RotatedRectangle as RRect


def draw_lane(world, lane, color=carla.Color(255, 0, 0), life_time=-1, height=0.2):
    locations = [carla.Location(p[0], -p[1], height)
                 for p in lane.leftEdge.lineString.coords]
    for i in range(len(locations)-1):
        begin = locations[i]
        end = locations[i+1]
        world.debug.draw_line(
            begin, end, thickness=0.1, color=color, life_time=life_time)
    locations = [carla.Location(p[0], -p[1], height)
                 for p in lane.rightEdge.lineString.coords]
    for i in range(len(locations)-1):
        begin = locations[i]
        end = locations[i+1]
        world.debug.draw_line(
            begin, end, thickness=0.1, color=color, life_time=life_time)


def draw_intersection(world, intersection, draw_lanes=False, arrival_distance=4, height=0.1):
    polygon = intersection.polygon

    # Boundaries of the intersection
    locs = [carla.Location(p[0], -p[1], height)
            for p in polygon.exterior.coords]
    for i in range(len(locs)):
        p0 = locs[i]
        p1 = locs[(i+1) % len(locs)]
        world.debug.draw_line(
            p0, p1, color=carla.Color(0, 0, 255), life_time=0)

    # Draw lane names
    for lane in intersection.incomingLanes:
        c = lane.centerline[-1]
        v = lane.flowFrom(c, -1)
        loc = carla.Location(v.x, -v.y, height)
        world.debug.draw_string(
            loc, lane.uid, draw_shadow=False, life_time=1000)
    for lane in intersection.outgoingLanes:
        c = lane.centerline[0]
        v = lane.flowFrom(c, 1)
        loc = carla.Location(v.x, -v.y, height)
        world.debug.draw_string(
            loc, lane.uid, draw_shadow=False, life_time=1000)

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

    if draw_lanes:
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

def draw_point_3d(world, point, height, size=0.1, color=carla.Color(255, 0, 0), lifetime=-1.0):
        loc = carla.Location(point.x, -point.y, height)
        world.debug.draw_point(loc, size, color, lifetime)

def draw_points(world, points):
    for p in points:
        loc = carla.Location(p.x, -p.y, 0.2)
        world.debug.draw_point(loc)

def draw_points_3d(world, points):
    for p in points:
        if p is list:
            x, y, z = p[0], -p[1], p[2]
        else:
            x, y, z = p[0], -p[1], p[2]
        loc = carla.Location(p[0], -p[1], p[2])
        world.debug.draw_point(loc)


def draw_rect(world, rect, height=0.1):
    corners = [carla.Location(p.x, -p.y, height) for p in rect.corners]
    for i in range(-1, len(corners)-1):
        world.debug.draw_line(corners[i], corners[i+1])
