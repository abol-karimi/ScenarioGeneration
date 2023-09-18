# Scenic parameters
model scenic.domains.driving.model

# Python imports
from itertools import product
from pathlib import Path
import pickle
import jsonpickle
from shapely.geometry import LineString
import carla

# from scenic.core.vectors import Orientation
from scenariogen.core.utils import sample_trajectories
from scenariogen.core.signals import SignalType
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError
from scenariogen.core.geometry import CurvilinearTransform

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
  blueprint2dims = jsonpickle.decode(f.read())

behavior AnimateBehavior(traj_sample):
	for pose in traj_sample:
		take SetTransformAction(pose[0]@pose[1], Orientation._fromHeading(pose[2]))

scenario NonegosScenario(config):
  setup:
    cars = []
    fuzz_input = config['fuzz_input']
    if config['replay_raw']:
      fuzz_input_path = Path(config['fuzz_input_path'])
      with open(fuzz_input_path.parents[1]/'seed_definitions'/f'{fuzz_input_path.stem}_sim_trajectories.pickle', 'rb') as f:
          sim_tjs = pickle.load(f)
      tjs = [[pose for pose, time in tj] for tj in sim_tjs]
    else:
      tjs = sample_trajectories(network, fuzz_input, int(config['steps'])+1, umax=config['steps']*config['timestep'])
    for i, (route, tj, signal, blueprint) in enumerate(zip(fuzz_input.routes,
                                                           tjs, 
                                                           fuzz_input.signals, 
                                                           fuzz_input.blueprints)):
      car = new Car at tj[0][0]@tj[0][1], facing tj[0][2],
        with name f'{route[0]}_{signal.name}_{i}',
        with blueprint blueprint,
        with length blueprint2dims[blueprint]['length'],
        with width blueprint2dims[blueprint]['width'],
        with color Color(0, 0, 1),
        with signal signal,
        with physics False,
        with allowCollisions False,
        with behavior AnimateBehavior(tj)
      cars.append(car)

monitor CheckCollisionsMonitor(cars1, cars2):
  while True:
    for c, d in product(cars1, cars2):
      if (not c is d) and c.intersects(d):
        raise NonegoNonegoCollisionError(c, d)
    wait
