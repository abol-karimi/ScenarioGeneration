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

class InvalidFuzzInputError(SUTError):
    """FuzzInput validation faild."""

    def __init__(self, message):
        self.msg = message

class NoASPSolutionError(Exception):
    """Exception raised for errors in ASP solving."""

    def __init__(self, message):
        self.msg = message
        
class NoSMTSolutionError(Exception):
    """Exception raised for errors in SMT solving."""

    def __init__(self, message):
        self.msg = message