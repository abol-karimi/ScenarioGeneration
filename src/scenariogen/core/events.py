def time_to_term(seconds):
    return f't{str(seconds).replace(".", "_")}'

def term_to_time(term):
    return float(term[1:].replace("_", "."))

class ArrivedAtIntersectionEvent:
    """Arrival of a vehicle at an intersection."""

    def __init__(self, vehicle, incoming_lane, seconds):
        self.vehicle = vehicle
        self.incoming_lane = incoming_lane
        self.seconds = seconds

    def __str__(self):
        return f'arrivedAtForkAtTime({self.vehicle}, {self.incoming_lane}, {time_to_term(self.seconds)})'


class SignaledEvent:
    """A vehicle signaling when turning, stopping, etc."""

    def __init__(self, vehicle, signal, seconds):
        self.vehicle = vehicle
        self.signal = signal
        self.seconds = seconds

    def __str__(self):
        return f'signaledAtTime({self.vehicle}, {self.signal}, {time_to_term(self.seconds)})'


class StoppedAtForkEvent:
    """Stopping after arrival at a stop sign and before entrance to the intersection."""

    def __init__(self, vehicle, incoming_lane, seconds):
        self.vehicle = vehicle
        self.incoming_lane = incoming_lane
        self.seconds = seconds

    def __str__(self):
        return f'stoppedAtForkAtTime({self.vehicle}, {self.incoming_lane}, {time_to_term(self.seconds)})'


class EnteredLaneEvent:
    """When part of a vehicle enters the lane."""

    def __init__(self, vehicle, lane, seconds):
        self.vehicle = vehicle
        self.lane = lane
        self.seconds = seconds

    def __str__(self):
        return f'enteredLaneAtTime({self.vehicle}, {self.lane}, {time_to_term(self.seconds)})'


class ExitedLaneEvent:
    """When the last part of a vehicle exits the lane."""

    def __init__(self, vehicle, lane, seconds):
        self.vehicle = vehicle
        self.lane = lane
        self.seconds = seconds

    def __str__(self):
        return f'leftLaneAtTime({self.vehicle}, {self.lane}, {time_to_term(self.seconds)})'


class EnteredIntersectionEvent:
    """When any part of a vehicle enters the intersection."""

    def __init__(self, vehicle, incoming_lane, seconds):
        self.vehicle = vehicle
        self.incoming_lane = incoming_lane
        self.seconds = seconds

    def __str__(self):
        return f'enteredForkAtTime({self.vehicle}, {self.incoming_lane}, {time_to_term(self.seconds)})'


class ExitedIntersectionEvent:
    """When the last part of a vehicle exits the intersection."""

    def __init__(self, vehicle, outgoing_lane, seconds):
        self.vehicle = vehicle
        self.outgoing_lane = outgoing_lane
        self.seconds = seconds

    def __str__(self):
        return f'exitedFromAtTime({self.vehicle}, {self.outgoing_lane}, {time_to_term(self.seconds)})'

