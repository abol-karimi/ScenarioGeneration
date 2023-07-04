#!/usr/bin/env python3.8
import jsonpickle
from pathlib import Path
from scenic.domains.driving.roads import Network
import argparse
import carla
import pickle

# This project
from scenariogen.core.seed import Seed
import scenariogen.simulators.carla.visualization as visualization
from scenariogen.core.utils import sample_trajectory

parser = argparse.ArgumentParser(description='play the given scenario.')
parser.add_argument('seed_path', help='relative path of the seed')
parser.add_argument('--timestep', type=float, default=0.05,
                    help='length of each simulation step, controls replay speed.')
parser.add_argument('--lifetime', type=float,
                    help='how long till drawings are erased')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int, help='max number of steps to replay')
duration.add_argument('--seconds', type=float, help='max seconds to replay')
args = parser.parse_args()

with open(args.seed_path, 'r') as f:
    seed = jsonpickle.decode(f.read())
    assert isinstance(seed, Seed)

# Default duration is the whole scenario:
steps = seed.trajectories[0].ctrlpts[-1][2]//args.timestep
# Restric the duration if requested:
if args.steps:
    steps = min(steps, args.steps)
elif args.seconds:
    steps = min(steps, args.seconds*args.timestep)

if args.lifetime:
   lifetime = args.lifetime
else:
   lifetime = steps*args.timestep

client = carla.Client('127.0.0.1', 2000)
world = client.get_world()

settings = world.get_settings()
settings.synchronous_mode = False
world.apply_settings(settings)

network = Network.fromFile(seed.config['map'])

seed_path = Path(args.seed_path)
with open(seed_path.parents[1]/'initial_seeds_definitions'/f'{seed_path.stem}_sim_trajectories.pickle', 'rb') as f:
    spacetime_trajectories = pickle.load(f)

#--- Draw the simulated trajectories
for tj in spacetime_trajectories:
  for p in tj:
    visualization.draw_point(world,
                             p,
                             size=0.1, 
                             color=carla.Color(0, 255, 0),
                             lifetime=lifetime)

#--- Draw the spline approximation of the trajectories
for spline in seed.trajectories:
  traj_sample = sample_trajectory(spline, 
                                  int(steps)+1,
                                  0, 
                                  args.timestep*steps)
  for i, p in enumerate(traj_sample):
    visualization.draw_point(world,
                             p, 
                             i*args.timestep, 
                             0.1, 
                             carla.Color(0, 0, 255),
                             lifetime)