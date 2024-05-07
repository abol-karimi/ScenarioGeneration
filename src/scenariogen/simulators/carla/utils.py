from more_itertools import pairwise
import math
import xml.etree.ElementTree as ET
from carla import VehicleLightState
from agents.navigation.global_route_planner import GlobalRoutePlanner
from agents.navigation.local_planner import RoadOption

from scenic.domains.driving.roads import ManeuverType
from scenic.core.vectors import Vector
from scenic.simulators.carla.utils.utils import scenicToCarlaLocation

from scenariogen.core.signals import SignalType
from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.core.utils import maneuvers_from_route

def signal_to_vehicleLightState(signal):
  if signal is SignalType.OFF:
    return VehicleLightState.NONE
  if signal is SignalType.LEFT:
    return VehicleLightState.LeftBlinker
  if signal is SignalType.RIGHT:
    return VehicleLightState.RightBlinker

def vehicleLightState_to_signal(vehicleLightState):
  if vehicleLightState & VehicleLightState.LeftBlinker:
    return SignalType.LEFT
  elif vehicleLightState & VehicleLightState.RightBlinker:
    return SignalType.RIGHT
  else:
    return SignalType.OFF

def maneuverType_to_Autopilot_turn(maneuver_type):
  if maneuver_type is ManeuverType.STRAIGHT:
    return 'Straight'
  if maneuver_type is ManeuverType.LEFT_TURN:
    return 'Left'
  if maneuver_type is ManeuverType.RIGHT_TURN:
    return 'Right'
  if maneuver_type is ManeuverType.U_TURN:
    return 'Left'


def get_latlon_ref(map_xodr):
    """
    Convert from waypoints world coordinates to CARLA GPS coordinates
    :return: tuple with lat and lon coordinates
    """
    tree = ET.ElementTree(ET.fromstring(map_xodr))

    # default reference
    lat_ref = 42.0
    lon_ref = 2.0

    for opendrive in tree.iter("OpenDRIVE"):
        for header in opendrive.iter("header"):
            for georef in header.iter("geoReference"):
                if georef.text:
                    str_list = georef.text.split(' ')
                    for item in str_list:
                        if '+lat_0' in item:
                            lat_ref = float(item.split('=')[1])
                        if '+lon_0' in item:
                            lon_ref = float(item.split('=')[1])
    return lat_ref, lon_ref


def location_to_gps(lat_ref, lon_ref, location):
    """
    Convert from world coordinates to GPS coordinates
    :param lat_ref: latitude reference for the current map
    :param lon_ref: longitude reference for the current map
    :param location: location to translate
    :return: dictionary with lat, lon and height
    """

    EARTH_RADIUS_EQUA = 6378137.0   # pylint: disable=invalid-name
    scale = math.cos(lat_ref * math.pi / 180.0)
    mx = scale * lon_ref * math.pi * EARTH_RADIUS_EQUA / 180.0
    my = scale * EARTH_RADIUS_EQUA * math.log(math.tan((90.0 + lat_ref) * math.pi / 360.0))
    mx += location.x
    my -= location.y

    lon = mx * 180.0 / (math.pi * EARTH_RADIUS_EQUA * scale)
    lat = 360.0 * math.atan(math.exp(my / (EARTH_RADIUS_EQUA * scale))) / math.pi - 90.0
    z = location.z

    return {'lat': lat, 'lon': lon, 'z': z}


def interpolate_trajectory(carla_map, waypoints_trajectory, hop_resolution=1.0):
    """
    Given some raw keypoints interpolate a full dense trajectory to be used by the user.
    returns the full interpolated route both in GPS coordinates and also in its original form.
    
    Args:
        - waypoints_trajectory: the current coarse trajectory
        - hop_resolution: distance between the trajectory's waypoints
    """

    grp = GlobalRoutePlanner(carla_map, hop_resolution)
    # Obtain route plan
    lat_ref, lon_ref = get_latlon_ref(carla_map.to_opendrive())

    route = []
    gps_route = []

    for i in range(len(waypoints_trajectory) - 1):

        waypoint = waypoints_trajectory[i]
        waypoint_next = waypoints_trajectory[i + 1]
        interpolated_trace = grp.trace_route(waypoint, waypoint_next)
        for wp, connection in interpolated_trace:
            route.append((wp.transform, connection))
            gps_coord = location_to_gps(lat_ref, lon_ref, wp.transform.location)
            gps_route.append((gps_coord, connection))

    return gps_route, route


def plan_from_route(world, carla_map, network, route, init_progress_ratio, waypoint_separation):
    """
    Given a route, return a list of waypoints
    """
    lanes = [network.elements[l] for l in route]
    
    # we assume that lanes[0] is not an intersection lane, so its waypoints' directions should be LANEFOLLOW:
    mType_to_rOption = {
        ManeuverType.STRAIGHT: RoadOption.LANEFOLLOW,
        ManeuverType.LEFT_TURN: RoadOption.LEFT,
        ManeuverType.RIGHT_TURN: RoadOption.RIGHT,
        ManeuverType.U_TURN: RoadOption.LEFT
    }
    directions = [RoadOption.LANEFOLLOW]
    directions.extend(mType_to_rOption[m.type] for m in maneuvers_from_route(lanes))

    # Find the first waypoint on the route
    transform = CurvilinearTransform([p for lane in lanes
                                        for p in lane.centerline.lineString.coords
                                        ])
    x0 = transform.axis.length * init_progress_ratio
    y0 = 0
    h0 = 0
    p0 = Vector(*transform.rectilinear(Vector(x0, y0), h0))
    loc0 = scenicToCarlaLocation(p0, world=world)
    wp0 = carla_map.get_waypoint(loc0)

    # Initially: plan contains all waypoints on lanes[0] starting at wp0, each with directions[0]
    current_lane_idx = 0
    plan = [(wp, directions[current_lane_idx]) for wp in [wp0] + wp0.next_until_lane_end(waypoint_separation)]
    # Invariant: plan contains all waypoints on lanes[current_lane_idx], each with directions[current_lane_idx]
    while current_lane_idx < len(lanes) - 1:
        potential_next_waypoints = plan[-1][0].next(waypoint_separation)
        potential_next_roads = {wp.road_id for wp in potential_next_waypoints}

        # skip lanes that don't reach the next waypoint
        while current_lane_idx < len(lanes) and not lanes[current_lane_idx].road.id in potential_next_roads:
            current_lane_idx += 1
        
        # if found a lane that reaches the next waypoint, add its waypoints to the plan
        if current_lane_idx < len(lanes):
            next_waypoint = [wp for wp in potential_next_waypoints if wp.road_id == lanes[current_lane_idx].road.id][0]
            next_direction = directions[current_lane_idx]
            plan.append((next_waypoint, next_direction))
            plan.extend((wp, next_direction) for wp in next_waypoint.next_until_lane_end(waypoint_separation))

    return plan


