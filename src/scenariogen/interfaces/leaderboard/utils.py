import carla
from agents.navigation.local_planner import RoadOption

def draw_waypoints(world, lifetime, waypoints, vertical_shift, size, downsample=1):
    """
    Draw a list of waypoints at a certain height given in vertical_shift.
    """
    for i, w in enumerate(waypoints):
        if i % downsample != 0:
            continue

        wp = w[0].location + carla.Location(z=vertical_shift)

        if w[1] == RoadOption.LEFT:  # Yellow
            color = carla.Color(128, 128, 0)
        elif w[1] == RoadOption.RIGHT:  # Cyan
            color = carla.Color(0, 128, 128)
        elif w[1] == RoadOption.CHANGELANELEFT:  # Orange
            color = carla.Color(128, 32, 0)
        elif w[1] == RoadOption.CHANGELANERIGHT:  # Dark Cyan
            color = carla.Color(0, 32, 128)
        elif w[1] == RoadOption.STRAIGHT:  # Gray
            color = carla.Color(64, 64, 64)
        else:  # LANEFOLLOW
            color = carla.Color(0, 128, 0)  # Green

        world.debug.draw_point(wp, size=size, color=color, life_time=lifetime)

    world.debug.draw_point(waypoints[0][0].location + carla.Location(z=vertical_shift), size=2*size,
                                color=carla.Color(0, 0, 128), life_time=lifetime)
    world.debug.draw_point(waypoints[-1][0].location + carla.Location(z=vertical_shift), size=2*size,
                                color=carla.Color(128, 128, 128), life_time=lifetime)