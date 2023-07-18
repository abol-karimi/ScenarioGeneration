#!/usr/bin/env python3.8
import argparse
import jsonpickle, pickle
import random
from pathlib import Path
import carla
import scenic
from scenic.core.object_types import OrientedPoint
from scenic.core.vectors import Vector
from scenic.domains.driving.roads import Network

# This project
from scenariogen.core.seed import Seed
from scenariogen.core.utils import sample_trajectories

parser = argparse.ArgumentParser(description='play the given scenario.')
parser.add_argument('seed_path', help='relative path of the seed')
parser.add_argument('--simulator', choices=['newtonian', 'carla'], default='newtonian',
                    help='The simulator')
parser.add_argument('--timestep', type=float, 
                    default=0.05, 
                    help='length of each simulation step, controls replay speed.')
parser.add_argument('--sim', action='store_true',
                    help='Replay the original simulation if available, instead of the spline approximation')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int, help='max number of steps to replay')
duration.add_argument('--seconds', type=float, help='max seconds to replay')
args = parser.parse_args()

with open(args.seed_path, 'r') as f:
    seed = jsonpickle.decode(f.read())
    assert isinstance(seed, Seed)

# Default duration is the whole scenario:
seconds = seed.timings[0].ctrlpts[-1][1]
# Override with custom duration:
if args.steps:
    seconds = args.steps * args.timestep
elif args.seconds:
    seconds = args.seconds
steps = int(seconds // args.timestep)

if args.sim:
    seed_path = Path(args.seed_path)
    with open(seed_path.parents[1]/'initial_seeds_definitions'/f'{seed_path.stem}_sim_trajectories.pickle', 'rb') as f:
        sim_trajs = pickle.load(f)
    traj_samples = []
    for traj in sim_trajs:
        traj_sample = []
        for s in traj:
            p = Vector(s[0], s[1])
            pose = OrientedPoint(position=p, heading=s[2])
            traj_sample.append(pose)
        traj_samples.append(traj_sample)
else:
    network = Network.fromFile(seed.config['map'])
    traj_samples = sample_trajectories(network, seed, steps+1)
    
config = {**seed.config}
config['steps'] = steps
config['timestep'] = args.timestep
config['weather'] = 'CloudySunset'
config['seed'] = seed
config['seed_path'] = args.seed_path
config['traj_samples'] = traj_samples

if args.simulator == 'carla':
    # Load the correct map to Carla, if necessary
    client = carla.Client('127.0.0.1', 2000)
    loaded_map = client.get_world().get_map().name
    if loaded_map != config['carla_map']:
        client.load_world(config['carla_map'])

    # Choose a blueprint of an appropriate size for each non-ego
    with open('src/scenariogen/simulators/carla/blueprint_library.json', 'r') as f:
        blueprints = jsonpickle.decode(f.read())
    dim2bp = {}
    for b, dims in blueprints.items():
        length = int(100*dims['length'])
        width = int(100*dims['width'])
        if not (length, width) in dim2bp:
            dim2bp[(length, width)] = [b]
        else:
            dim2bp[(length, width)].append(b)
    bps = [random.choice(dim2bp[(int(l*100), int(w*100))])
        for l, w in zip(seed.lengths, seed.widths)]
    config['blueprints'] = bps

# Run the scenario on the seed
params = {'carla_map': seed.config['carla_map'],
          'map': seed.config['map'],
          'config': config,
          'timestep': args.timestep,
          'render': True
          }

scenic_scenario = scenic.scenarioFromFile(
    f'src/scenariogen/scripts/{args.simulator}/replay.scenic',
    params=params)

scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = scenic_scenario.getSimulator()
sim_result = simulator.simulate(
                scene,
                maxSteps=config['steps'],
                maxIterations=1,
                raiseGuardViolations=True
                )