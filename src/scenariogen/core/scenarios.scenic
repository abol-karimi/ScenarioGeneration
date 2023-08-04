# Scenic parameters
model scenic.domains.driving.model
config = globalParameters.config
intersection = network.elements[config['intersection']]

# Python imports
from pathlib import Path
import pickle
from shapely.geometry import LineString

from scenic.core.vectors import Orientation
from scenariogen.core.utils import sample_trajectories
from scenariogen.core.signals import SignalType
from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError
from scenariogen.core.utils import is_collision_free
from scenariogen.core.geometry import CurvilinearTransform

behavior AnimateBehavior():
	for pose in self.traj_sample:
		take SetPositionAction(pose[0]@pose[1]), SetHeadingAction(pose[2])

behavior StopAndPassIntersectionBehavior(speed, trajectory, intersection, arrival_distance=4):
  do FollowTrajectoryBehavior(speed, trajectory) until (distance from (front of self) to intersection) <= arrival_distance
  do StopBehavior() until self.speed <= 0.1
  do FollowTrajectoryBehavior(speed, trajectory)
  do FollowLaneBehavior(speed)

scenario NonegosScenario():
  setup:
    cars = []
    fuzz_input = config['fuzz_input']
    if config['replay_raw']:
      fuzz_input_path = Path(config['fuzz_input_path'])
      with open(fuzz_input_path.parents[1]/'seeds_definitions'/f'{fuzz_input_path.stem}_sim_trajectories.pickle', 'rb') as f:
          sim_tjs = pickle.load(f)
      tjs = [[pose for pose, time in tj] for tj in sim_tjs]
    else:
      tjs = sample_trajectories(network, fuzz_input, int(config['steps'])+1, umax=config['steps']*config['timestep'])
    for i, (route, tj, signal, l, w, bp) in enumerate(zip(fuzz_input.routes, tjs, fuzz_input.signals, fuzz_input.lengths, fuzz_input.widths, config['blueprints'])):
      route_list = list(route)
      car = new Car at tj[0][0]@tj[0][1],
        with name f'{route_list[0]}_{signal.name}_{i}',
        with behavior AnimateBehavior(),
        with physics False,
        with allowCollisions False,
        with traj_sample tj,
        with signal signal,
        with length l,
        with width w,
        with blueprint bp
      cars.append(car)

scenario CheckCollisionsScenario(egos, nonegos):
  setup:
    monitor collisions():
      nonego_pairs = [(nonegos[i], nonegos[j]) 
              for i in range(len(nonegos)) 
              for j in range(i+1, len(nonegos))]
      ego_nonego_pairs = [(e, n) for e in egos for n in nonegos]
      while True:
        # Nonego-nonego collisions
        for c, d in nonego_pairs:
          if c.intersects(d):
            raise NonegoNonegoCollisionError(c, d)
        # Ego-nonego collisions
        for e, n in ego_nonego_pairs:
          if e.intersects(n):
            raise EgoCollisionError(e, n)
        wait

poses = []
scenario RecordSimTrajectories(cars):
  setup:

    monitor record_poses():
      while True:
        poses.append(tuple((car.position, car.heading) for car in cars))
        wait

    record final poses as poses