#!/usr/bin/env python3.8

# Standard libraries
import importlib
import argparse
import pickle
import jsonpickle

# Scenic modules
from scenic.domains.driving.roads import Network

# My modules
import seed
# import mutator
import fuzzers
from signals import SignalType

# Mutator configs
config = {}
config['maxSteps'] = 700
config['timestep'] = 0.05
config['weather'] = 'CloudySunset'
config['map_path'] = './maps/Town05.xodr'
config['map_name'] = 'Town05'
config['intersection_uid'] = 'intersection396'
config['rules_path'] = '4way-stopOnAll.lp'
config['arrival_distance'] = 4
config['network'] = Network.fromFile(config['map_path'])
# mutator = mutator.Mutator(config)

network = config['network']
intersection = network.elements[config['intersection_uid']]
routes = [(m.startLane, m.connectingLane, m.endLane)
          for m in intersection.maneuvers]
config['ego_route']= [l.uid for l in routes[0]]
config['ego_distance'] = 10

final_time = config['maxSteps']*config['timestep']

def route_length(route):
  return sum([l.centerline.length for l in route])

route0 = routes[1]
curve0 = seed.ParameterizedCurve([seed.ControlPoint(0, 0),
                                  seed.ControlPoint(final_time/3, 0),
                                  seed.ControlPoint(final_time*2/3, 0),
                                  seed.ControlPoint(final_time, 2/3*route_length(route0))])
seed0 = seed.Seed(routes=[[l.uid for l in route0]], curves=[curve0], signals=[SignalType.LEFT])
initial_seeds = [seed0]

num_fuzzing_steps = 2
fuzzer = fuzzers.RandomFuzzer(config=config)
seeds = fuzzer.run(initial_seeds, num_fuzzing_steps)

# Write to file
# with open('seeds.', 'wb') as outFile:
#     pickle.dump(scenario, outFile)