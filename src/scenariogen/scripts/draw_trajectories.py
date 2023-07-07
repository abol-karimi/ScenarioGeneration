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
parser.add_argument('--lifetime', type=float, default=20,
                    help='how long the drawings last')
args = parser.parse_args()

with open(args.seed_path, 'r') as f:
    seed = jsonpickle.decode(f.read())
    assert isinstance(seed, Seed)

client = carla.Client('127.0.0.1', 2000)
world = client.get_world()

settings = world.get_settings()
settings.synchronous_mode = False
world.apply_settings(settings)

network = Network.fromFile(seed.config['map'])

seed_path = Path(args.seed_path)
with open(seed_path.parents[1]/'initial_seeds_definitions'/f'{seed_path.stem}_sim_trajectories.pickle', 'rb') as f:
    sim_trajectories = pickle.load(f)

#--- Draw the simulated trajectories, in green
for tj in sim_trajectories:
  for p in tj:
    visualization.draw_point(world,
                             (p[0], p[1], p[3]),
                             size=0.1, 
                             color=carla.Color(0, 255, 0),
                             lifetime=args.lifetime)

#--- Draw the spline approximation of the trajectories, in blue
resolution = 0.05
interval = (0, seed.trajectories[0].ctrlpts[-1][2])
steps = int(interval[1] // resolution)
for spline in seed.trajectories:
  traj_sample = sample_trajectory(spline, 
                                  steps+1,
                                  interval[0], 
                                  interval[1])
  for i, p in enumerate(traj_sample):
    visualization.draw_point(world,
                             p, 
                             i*resolution, 
                             0.1, 
                             carla.Color(0, 0, 255),
                             args.lifetime)