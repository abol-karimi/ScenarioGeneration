from abc import ABC, abstractmethod


class ActorEvent(ABC):
    def __init__(self, vehicle, time):
        self.vehicle = vehicle
        self.time = time

    @abstractmethod
    def simplified(self):
        pass

    @abstractmethod
    def __repr__(self):
        pass

    def __str__(self):
        return repr(self.simplified())

class ArrivedAtIntersectionEvent(ActorEvent):
    """Arrival of a vehicle at an intersection."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane
    
    def simplified(self):
        return ArrivedAtIntersectionEvent(self.vehicle.name, self.lane.uid, self.time)

    def __repr__(self):
        return f'arrivedFromLaneAtTime({self.vehicle}, {self.lane}, {self.time})'
   

class SignaledEvent(ActorEvent):
    """A vehicle signaling when turning, stopping, etc."""

    def __init__(self, vehicle, signal, time):
        super().__init__(vehicle, time)
        self.signal = signal

    def simplified(self):
        return SignaledEvent(self.vehicle.name, self.signal.name.lower(), self.time)

    def __repr__(self):
        return f'signaledAtTime({self.vehicle}, {self.signal}, {self.time})'


class StoppedEvent(ActorEvent):
    """Slowing down to a speed threshold or less."""

    def simplified(self):
        return StoppedEvent(self.vehicle.name, self.time)

    def __repr__(self):
        return f'stoppedAtTime({self.vehicle}, {self.time})'


class MovedEvent(ActorEvent):
    """Speeding up to a speed threshold or more."""

    def simplified(self):
        return MovedEvent(self.vehicle.name, self.time)

    def __repr__(self):
        return f'movedAtTime({self.vehicle}, {self.time})'


class EnteredLaneEvent(ActorEvent):
    """When part of a vehicle enters the region."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane

    def simplified(self):
        return EnteredLaneEvent(self.vehicle.name, self.lane.uid, self.time)

    def __repr__(self):
        return f'enteredLaneAtTime({self.vehicle}, {self.lane}, {self.time})'


class EnteredIntersectionEvent(ActorEvent):
    """When part of a vehicle enters the region."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane

    def simplified(self):
        return EnteredIntersectionEvent(self.vehicle.name, self.lane.uid, self.time)

    def __repr__(self):
        return f'enteredFromLaneAtTime({self.vehicle}, {self.lane}, {self.time})'


class LeftLaneEvent(ActorEvent):
    """When the last part of a vehicle exits the region."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane

    def simplified(self):
        return LeftLaneEvent(self.vehicle.name, self.lane.uid, self.time)

    def __repr__(self):
        return f'leftLaneAtTime({self.vehicle}, {self.lane}, {self.time})'


class LeftIntersectionEvent(ActorEvent):
    """When the last part of a vehicle exits the region."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane

    def simplified(self):
        return LeftIntersectionEvent(self.vehicle.name, self.lane.uid, self.time)

    def __repr__(self):
        return f'leftToLaneAtTime({self.vehicle}, {self.lane}, {self.time})'


class AppearedToOtherEvent(ActorEvent):
    """Becoming visible to another agent."""

    def __init__(self, vehicle, other, time):
        super().__init__(vehicle, time)
        self.other = other

    def simplified(self):
        return AppearedToOtherEvent(self.vehicle.name, self.other.name, self.time)

    def __repr__(self):
        return f'appearedToAtTime({self.vehicle}, {self.other}, {self.time})'


class DisappearedFromOtherEvent(ActorEvent):
    """Becoming invisible to another agent."""

    def __init__(self, vehicle, other, time):
        super().__init__(vehicle, time)
        self.other = other

    def simplified(self):
        return DisappearedFromOtherEvent(self.vehicle.name, self.other.name, self.time)

    def __repr__(self):
        return f'disappearedFromAtTime({self.vehicle}, {self.other}, {self.time})'


class ActorSpawnedEvent(ActorEvent):
    """Reporting the actors present in the scenario."""

    def __init__(self, vehicle, lane, progress, time):
        super().__init__(vehicle, time)
        self.lane = lane
        self.progress = progress
    
    def simplified(self):
        return ActorSpawnedEvent(self.vehicle.name, self.lane.uid, int(self.progress), self.time)

    def __repr__(self):
        return f'actorSpawnedAtAlongLaneAtTime({self.vehicle}, {self.progress}, {self.lane}, {self.time})'


class ActorDestroyedEvent(ActorEvent):
    """Reporting the actors present in the scenario."""
   
    def simplified(self):
        return ActorDestroyedEvent(self.vehicle.name, self.time)

    def __repr__(self):
        return f'actorDestroyedAtTime({self.vehicle}, {self.time})'


class CollisionEvent(ActorEvent):
    """Collision with other actors or props."""

    def __init__(self, vehicle, other, time):
        super().__init__(vehicle, time)
        self.other = other

    def simplified(self):
        return CollisionEvent(self.vehicle.name, self.other.name, self.time)

    def __repr__(self):
        return f'collidedWithAtTime({self.vehicle}, {self.other}, {self.time})'