class SUTError(Exception):
    """An error occurred during the execution of the System Under Test (SUT)."""
    pass

class EgoCollisionError(SUTError):
    """Ego collides with another vehicle."""
    def __init__(self, ego, other):
        self.ego = ego
        self.other = other

class NonegoNonegoCollisionError(SUTError):
    """Two non-egos collide, so the seed is invalid."""
    def __init__(self, nonego, other):
        self.nonego = nonego
        self.other = other

class InvalidSeedError(SUTError):
    """Seed validation faild."""
    def __init__(self, message):
        self.msg = message
