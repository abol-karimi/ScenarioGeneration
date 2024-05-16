from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SimResult:
    trajectory : Any = None
    finalState : Any = None
    terminationType : Any = None
    terminationReason : Any = None
    records : Any = None

    @classmethod
    def from_simulation(cls, simulation):
        result = simulation.result
        return cls(result.trajectory,
                    result.finalState,
                    result.terminationType,
                    result.terminationReason,
                    result.records)