from scenariogen.core.signals import SignalType
from carla import VehicleLightState

def signal_to_vehicleLightState(signal):
  if signal is SignalType.OFF:
    return VehicleLightState.NONE
  if signal is SignalType.LEFT:
    return VehicleLightState.LeftBlinker
  if signal is SignalType.RIGHT:
    return VehicleLightState.RightBlinker

def vehicleLightState_to_signal(vehicleLightState):
  if vehicleLightState is VehicleLightState.NONE:
    return SignalType.OFF
  if vehicleLightState is VehicleLightState.LeftBlinker:
    return SignalType.LEFT
  if vehicleLightState is VehicleLightState.RightBlinker:
    return SignalType.RIGHT