from carla import VehicleLightState
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
