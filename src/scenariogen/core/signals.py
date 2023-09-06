from scenic.domains.driving.roads import ManeuverType
import enum


@enum.unique
class SignalType(enum.Enum):
    """Turn signal at an intersection."""
    OFF = enum.auto()
    LEFT = enum.auto()
    RIGHT = enum.auto()

    @classmethod
    def from_maneuver_type(cls, maneuver_type):
        if maneuver_type is ManeuverType.STRAIGHT:
            return SignalType.OFF
        if maneuver_type is ManeuverType.LEFT_TURN:
            return SignalType.LEFT
        if maneuver_type is ManeuverType.RIGHT_TURN:
            return SignalType.RIGHT
        if maneuver_type is ManeuverType.U_TURN:
            return SignalType.LEFT