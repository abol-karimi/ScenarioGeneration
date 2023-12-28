import math
import xml.etree.ElementTree as ET
from carla import VehicleLightState
from agents.navigation.global_route_planner import GlobalRoutePlanner
from scenic.domains.driving.roads import ManeuverType
from scenariogen.core.signals import SignalType

def signal_to_vehicleLightState(signal):
  if signal is SignalType.OFF:
    return VehicleLightState.NONE
  if signal is SignalType.LEFT:
    return VehicleLightState.LeftBlinker
  if signal is SignalType.RIGHT:
    return VehicleLightState.RightBlinker

def vehicleLightState_to_signal(vehicleLightState):
  if vehicleLightState.LeftBlinker:
    return SignalType.LEFT
  elif vehicleLightState.RightBlinker:
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
