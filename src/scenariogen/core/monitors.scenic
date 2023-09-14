# Scenic parameters
model scenic.domains.driving.model

# Python imports
from itertools import product

from scenariogen.core.errors import NonegoNonegoCollisionError

monitor CheckCollisionsMonitor(cars1, cars2):
  while True:
    for c, d in product(cars1, cars2):
      if (not c is d) and c.intersects(d):
        raise NonegoNonegoCollisionError(c, d)
    wait
