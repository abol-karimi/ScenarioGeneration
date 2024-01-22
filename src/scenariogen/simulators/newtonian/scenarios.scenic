# Scenic parameters
model scenic.simulators.newtonian.driving_model

# Python imports
from itertools import product
from pathlib import Path
import pickle
import jsonpickle
from shapely.geometry import LineString
import carla
from scenic.core.type_support import toOrientation

from scenariogen.core.utils import sample_trajectories, sample_signal_actions
from scenariogen.core.signals import SignalType
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError
from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.simulators.carla.utils import signal_to_vehicleLightState

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

behavior AnimateBehavior(traj, signal_actions):
  for pose in traj:
    take SetPoseAction(pose[0]@pose[1], pose[2])

scenario NonegosScenario(config):
  setup:
    cars = []
    fuzz_input = config['fuzz-input']
    tjs = sample_trajectories(network, fuzz_input, int(config['steps'])+1)
    signals_actions = sample_signal_actions(fuzz_input, int(config['steps'])+1)
    for route, tj, timing, signal_actions, blueprint in zip(fuzz_input.routes,
                                                           tjs,
                                                           fuzz_input.timings,
                                                           signals_actions,
                                                           fuzz_input.blueprints):
      car = new Car at tj[0][0]@tj[0][1], facing tj[0][2],
        with name f'{route[0]}_{int(10*timing.ctrlpts[0][1])}',
        with blueprint blueprint,
        with length blueprint2dims[blueprint]['length'],
        with width blueprint2dims[blueprint]['width'],
        with color Color(0, 0, 1),
        with physics False,
        with allowCollisions False,
        with behavior AnimateBehavior(tj, signal_actions)
      cars.append(car)

