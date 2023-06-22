#!/usr/bin/env python3.8
from scenic.domains.driving.roads import Network
import argparse
import carla
import pickle

# This project
import scenariogen.core.seed_corpus as seed_corpus
import scenariogen.simulators.carla.visualization as visualization
from scenariogen.core.utils import sample_trajectory

parser = argparse.ArgumentParser(description='play the given scenario.')
parser.add_argument('corpus', 
                    help='filename of the corpus of seeds')
parser.add_argument('seed', type=int, 
                    help='seed number to replay')
parser.add_argument('--timestep', type=float, default=0.05, 
                    help='length of each simulation step, controls replay speed.')
parser.add_argument('--lifetime', type=float, 
                    help='how long till drawings are erased')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int, help='max number of steps to replay')
duration.add_argument('--seconds', type=float, help='max seconds to replay')
args = parser.parse_args()

corpus = seed_corpus.SeedCorpus([])
corpus.load(args.corpus)
seed = corpus.seeds[args.seed]

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

# Keep all the config parameters in one place
config = {}
config['steps'] = steps
config['timestep'] = args.timestep
config['lifetime'] = lifetime
config['weather'] = 'CloudySunset'
config['map_path'] = './maps/Town05.xodr'
config['map_name'] = 'Town05'
config['intersection_uid'] = 'intersection396'
config['arrival_distance'] = 4
config['network'] = Network.fromFile(config['map_path'])

map_name = config['map_name']
map_path = f'./maps/{map_name}.xodr'

client = carla.Client('127.0.0.1', 2000)
world = client.get_world()
network = Network.fromFile(map_path)

with open('spacetime_trajectories.pickle', 'rb') as inFile:
  spacetime_trajectories = pickle.load(inFile)

#--- Draw the simulated trajectories
for tj in spacetime_trajectories:
  for p in tj:
    visualization.draw_point(world,
                             p,
                             size=0.1, 
                             color=carla.Color(0, 255, 0),
                             lifetime=config['lifetime'])

#--- Draw the spline approximation of the trajectories
for spline in seed.trajectories:
  traj_sample = sample_trajectory(spline, 
                                  int(config['steps'])+1,
                                  0, 
                                  config['timestep']*config['steps'])
  for i, p in enumerate(traj_sample):
    visualization.draw_point(world,
                             p, 
                             i*config['timestep'], 
                             0.1, 
                             carla.Color(0, 0, 255),
                             config['lifetime'])