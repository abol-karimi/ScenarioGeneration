#!/usr/bin/env python3.8
import argparse
import jsonpickle
import random
import scenic
import carla

# This project
import scenariogen.core.seed_corpus as seed_corpus

parser = argparse.ArgumentParser(description='play the given scenario.')
parser.add_argument('corpus', help='filename of the corpus of seeds')
parser.add_argument('seed', type=int, help='seed number to replay')
parser.add_argument('--timestep', type=float, 
                    default=0.05, 
                    help='length of each simulation step, controls replay speed.')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int, help='max number of steps to replay')
duration.add_argument('--seconds', type=float, help='max seconds to replay')
simulator = parser.add_mutually_exclusive_group()
simulator.add_argument('--newtonian', action='store_const', dest='simulator', const='newtonian', 
                      help='replay in the newtonian simulator')
simulator.add_argument('--carla', action='store_const', dest='simulator', const='carla',
                      help='replay in the carla simulator')
args = parser.parse_args()

corpus = seed_corpus.SeedCorpus([])
corpus.load(args.corpus)
seed = corpus.seeds[args.seed]

# Default duration is the whole scenario:
seconds = seed.trajectories[0].ctrlpts[-1][2]
# Override with custom duration:
if args.steps:
    seconds = args.steps * args.timestep
elif args.seconds:
    seconds = args.seconds
steps = seconds // args.timestep

config = {}

if args.simulator == 'carla':
    # Load the correct map to Carla, if necessary
    client = carla.Client('127.0.0.1', 2000)
    loaded_map = client.get_world().get_map().name
    if loaded_map != corpus.config['carla_map']:
        client.load_world(corpus.config['carla_map'])

    # Choose a blueprint of an appropriate size for each non-ego
    with open('blueprint_library.json', 'r') as f:
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

config['steps'] = steps
config['timestep'] = args.timestep
config['weather'] = 'CloudySunset'
config['intersection'] = corpus.config['intersection']

# Run the scenario on the seed
params = {'carla_map': corpus.config['carla_map'],
          'map': corpus.config['map'],
          'config': config,
          'timestep': args.timestep,
          'render': True,
          'seed': seed}

scenic_scenario = scenic.scenarioFromFile(
    f'src/scenariogen/simulators/{args.simulator}/replay.scenic', 
    params=params)

scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = scenic_scenario.getSimulator()
sim_result = simulator.simulate(
                scene,
                maxSteps=config['steps'],
                maxIterations=1,
                raiseGuardViolations=True
                )