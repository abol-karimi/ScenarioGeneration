from scenariogen.core.signals import SignalType
from carla import VehicleLightState

def signal_to_vehicleLightState(signal):
  if signal is SignalType.OFF:
    return VehicleLightState.NONE
  if signal is SignalType.LEFT:
    return VehicleLightState.LeftBlinker
  if signal is SignalType.RIGHT:
    return VehicleLightState.RightBlinker