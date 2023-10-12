from scenic.domains.driving.roads import Lane, Intersection

from scenariogen.predicates.utils import time_to_term

class ArrivedAtIntersectionEvent:
    """Arrival of a vehicle at an intersection."""

    def __init__(self, vehicle, lane, seconds):
        self.vehicle = vehicle
        self.lane = lane
        self.seconds = seconds

    def __str__(self):
        return f'arrivedFromLaneAtTime({self.vehicle.name}, {self.lane.uid}, {time_to_term(self.seconds)})'


class SignaledEvent:
    """A vehicle signaling when turning, stopping, etc."""

    def __init__(self, vehicle, signal, seconds):
        self.vehicle = vehicle
        self.signal = signal
        self.seconds = seconds

    def __str__(self):
        return f'signaledAtTime({self.vehicle.name}, {self.signal.name.lower()}, {time_to_term(self.seconds)})'


class StoppedEvent:
    """Slowing down to a speed threshold or less."""

    def __init__(self, vehicle, seconds):
        self.vehicle = vehicle
        self.seconds = seconds

    def __str__(self):
        return f'stoppedAtTime({self.vehicle.name}, {time_to_term(self.seconds)})'


class MovedEvent:
    """Speeding up to a speed threshold or more."""

    def __init__(self, vehicle, seconds):
        self.vehicle = vehicle
        self.seconds = seconds

    def __str__(self):
        return f'movedAtTime({self.vehicle.name}, {time_to_term(self.seconds)})'


class EnteredRegionEvent:
    """When part of a vehicle enters the region."""

    def __init__(self, vehicle, region, seconds):
        self.vehicle = vehicle
        self.region = region
        self.seconds = seconds

    def __str__(self):
        if isinstance(self.region, Lane):
            predicate = 'enteredLaneAtTime'
        elif isinstance(self.region, Intersection):
            predicate = 'enteredIntersectionAtTime'

        return f'{predicate}({self.vehicle.name}, {self.region.uid}, {time_to_term(self.seconds)})'


class LeftRegionEvent:
    """When the last part of a vehicle exits the region."""

    def __init__(self, vehicle, region, seconds):
        self.vehicle = vehicle
        self.region = region
        self.seconds = seconds

    def __str__(self):
        if isinstance(self.region, Lane):
            predicate = 'leftLaneAtTime'
        elif isinstance(self.region, Intersection):
            predicate = 'leftIntersectionAtTime'

        return f'{predicate}({self.vehicle.name}, {self.region.uid}, {time_to_term(self.seconds)})'
