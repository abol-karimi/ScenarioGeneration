from abc import ABC, abstractmethod


class AgentEvent(ABC):
    def __init__(self, vehicle, time):
        self.vehicle = vehicle
        self.time = time

    @abstractmethod
    def __str__(self):
        pass


class ArrivedAtIntersectionEvent(AgentEvent):
    """Arrival of a vehicle at an intersection."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane

    def __str__(self):
        return f'arrivedFromLaneAtTime({self.vehicle}, {self.lane}, {self.time})'
   

class SignaledEvent(AgentEvent):
    """A vehicle signaling when turning, stopping, etc."""

    def __init__(self, vehicle, signal, time):
        super().__init__(vehicle, time)
        self.signal = signal

    def __str__(self):
        return f'signaledAtTime({self.vehicle}, {self.signal}, {self.time})'


class StoppedEvent(AgentEvent):
    """Slowing down to a speed threshold or less."""

    def __str__(self):
        return f'stoppedAtTime({self.vehicle}, {self.time})'


class MovedEvent(AgentEvent):
    """Speeding up to a speed threshold or more."""

    def __str__(self):
        return f'movedAtTime({self.vehicle}, {self.time})'


class EnteredLaneEvent(AgentEvent):
    """When part of a vehicle enters the region."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane

    def __str__(self):
        return f'enteredLaneAtTime({self.vehicle}, {self.lane}, {self.time})'


class EnteredIntersectionEvent(AgentEvent):
    """When part of a vehicle enters the region."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane

    def __str__(self):
        return f'enteredFromLaneAtTime({self.vehicle}, {self.lane}, {self.time})'


class LeftLaneEvent(AgentEvent):
    """When the last part of a vehicle exits the region."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane

    def __str__(self):
        return f'leftLaneAtTime({self.vehicle}, {self.lane}, {self.time})'


class LeftIntersectionEvent(AgentEvent):
    """When the last part of a vehicle exits the region."""

    def __init__(self, vehicle, lane, time):
        super().__init__(vehicle, time)
        self.lane = lane

    def __str__(self):
        return f'leftToLaneAtTime({self.vehicle}, {self.lane}, {self.time})'


class AppearedToOtherEvent(AgentEvent):
    """Becoming visible to another agent."""

    def __init__(self, vehicle, other, time):
        super().__init__(vehicle, time)
        self.other = other

    def __str__(self):
        return f'appearedToAtTime({self.vehicle}, {self.other}, {self.time})'


class DisappearedFromOtherEvent(AgentEvent):
    """Becoming invisible to another agent."""

    def __init__(self, vehicle, other, time):
        super().__init__(vehicle, time)
        self.other = other

    def __str__(self):
        return f'disappearedFromAtTime({self.vehicle}, {self.other}, {self.time})'


class AgentSpawnedEvent(AgentEvent):
    """Reporting the agents present in the scenario."""

    def __init__(self, vehicle, lane, progress, time):
        super().__init__(vehicle, time)
        self.lane = lane
        self.progress = progress
    
    def __str__(self):
        return f'agentSpawnedAtAlongLaneAtTime({self.vehicle}, {self.progress}, {self.lane}, {self.time})'


class AgentDestroyedEvent(AgentEvent):
    """Reporting the agents present in the scenario."""
   
    def __str__(self):
        return f'agentDestroyedAtTime({self.vehicle}, {self.time})'


class CollisionEvent(AgentEvent):
    """Collision with other actors or props."""

    def __init__(self, vehicle, other, time):
        super().__init__(vehicle, time)
        self.other = other

    def __str__(self):
        return f'collidedWithAtTime({self.vehicle}, {self.other}, {self.time})'