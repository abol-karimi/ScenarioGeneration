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

    def __init__(self, vehicle, region, lane, seconds):
        self.vehicle = vehicle
        self.region = region
        self.lane = lane
        self.seconds = seconds

    def __str__(self):
        if isinstance(self.region, Lane):
            return f'enteredLaneAtTime({self.vehicle.name}, {self.region.uid}, {time_to_term(self.seconds)})'
        elif isinstance(self.region, Intersection):
            return f'enteredFromLaneAtTime({self.vehicle.name}, {self.lane.uid}, {time_to_term(self.seconds)})'


class LeftRegionEvent:
    """When the last part of a vehicle exits the region."""

    def __init__(self, vehicle, region, lane, seconds):
        self.vehicle = vehicle
        self.region = region
        self.lane = lane
        self.seconds = seconds

    def __str__(self):
        if isinstance(self.region, Lane):
            return f'leftLaneAtTime({self.vehicle.name}, {self.region.uid}, {time_to_term(self.seconds)})'
        elif isinstance(self.region, Intersection):
            return f'leftToLaneAtTime({self.vehicle.name}, {self.lane.uid}, {time_to_term(self.seconds)})'       


class AppearedToOtherEvent:
    """Becoming visible to another agent."""

    def __init__(self, vehicle, other, seconds):
        self.vehicle = vehicle
        self.other = other
        self.seconds = seconds

    def __str__(self):
        return f'appearedToAtTime({self.vehicle.name}, {self.other.name}, {time_to_term(self.seconds)})'


class DisappearedFromOtherEvent:
    """Becoming invisible to another agent."""

    def __init__(self, vehicle, other, seconds):
        self.vehicle = vehicle
        self.other = other
        self.seconds = seconds

    def __str__(self):
        return f'disappearedFromAtTime({self.vehicle.name}, {self.other.name}, {time_to_term(self.seconds)})'


class ActorSpawnedEvent:
    """Reporting the actors present in the scenario.
    Assuming conservation of actors throught the scenario,
    the list is static, so no time parameter needed.
    """

    def __init__(self, vehicle, seconds):
        self.vehicle = vehicle
        self.seconds = seconds
    
    def __str__(self):
        return f'actorSpawnedAtTime({self.vehicle.name}, {time_to_term(self.seconds)})'


class ActorDestroyedEvent:
    """Reporting the actors present in the scenario.
    Assuming conservation of actors throught the scenario,
    the list is static, so no time parameter needed.
    """

    def __init__(self, vehicle, seconds):
        self.vehicle = vehicle
        self.seconds = seconds
    
    def __str__(self):
        return f'actorDestroyedEvent({self.vehicle.name}, {time_to_term(self.seconds)})'