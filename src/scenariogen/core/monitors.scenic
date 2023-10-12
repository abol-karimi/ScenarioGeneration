# Scenic parameters
model scenic.domains.driving.model

# Python imports
from itertools import product

from scenariogen.core.errors import NonegoCollisionError

monitor RaiseOverlapsMonitor(cars1, cars2):
  while True:
    for c, d in product(cars1, cars2):
      if (not c is d) and c.intersects(d):
        raise NonegoCollisionError(c, d)
    wait

monitor RequireOnRoadMonitor():
  cars = simulation().agents
  while True:
    for car in cars:
      require car.position in road
    wait
