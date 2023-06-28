class SUTError(Exception):
    """An error occurred during the execution of the System Under Test (SUT)."""
    pass

class EgoCollisionError(SUTError):
    """Ego collides with another vehicle."""
    pass

class InvalidSeedError(SUTError):
    """The seed is invalid, e.g. two non-egos collide."""
    pass