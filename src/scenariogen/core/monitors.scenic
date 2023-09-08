# Scenic parameters
model scenic.domains.driving.model
# config = globalParameters.config

# Python imports
from itertools import product
from pathlib import Path
import pickle
from shapely.geometry import LineString
import carla

from scenariogen.core.utils import sample_trajectories
from scenariogen.core.signals import SignalType
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError
from scenariogen.core.geometry import CurvilinearTransform

monitor CheckCollisionsMonitor(cars1, cars2):
  while True:
    for c, d in product(cars1, cars2):
      if (not c is d) and c.intersects(d):
        raise NonegoNonegoCollisionError(c, d)
    wait

monitor RecordPosesMonitor(cars, poses):
  while True:
    poses.append(tuple((car.position, car.heading) for car in cars))
    wait
