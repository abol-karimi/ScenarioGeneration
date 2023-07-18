#!/usr/bin/env python3.8

# External libraries
import numpy as np
import jsonpickle
import carla

# This project
from src.scenariogen.core.mutators import StructureAwareMutator
from scenariogen.core.seed import Seed
import scenariogen.simulators.carla.visualization as visualization
from scenariogen.core.utils import sample_trajectories

# Connect to the Carla simulator
client = carla.Client('127.0.0.1', 2000)
world = client.get_world()

settings = world.get_settings()
settings.synchronous_mode = False
world.apply_settings(settings)

# Load a seed, plot its trajectory
with open('experiments/initial_seeds/0.json', 'r') as f:
    seed = jsonpickle.decode(f.read())
    assert isinstance(seed, Seed)

mutator = StructureAwareMutator(max_parameters_size=50,
                        max_mutations_per_iteration=1,
                        randomizer_seed=0)
network = StructureAwareMutator.get_network(seed)

resolution = 0.05
idx = 1
umin, umax = 0, seed.timings[idx].ctrlpts[-1][1]
sample_size =  int((umax - umin) / resolution)
tjs = sample_trajectories(network, seed, sample_size)
tj = tjs[idx]
ts = np.linspace(umin, umax, num=sample_size)
for pose, t in zip(tj, ts):
    visualization.draw_point(world, (pose.x, pose.y), t, 
                            size=0.1,
                            color=carla.Color(0, 0, 255),
                            lifetime=300)

# Copy the trajectory with a longitudinal offset, then plot the new trajectory
offset = 20
mutant = mutator.move_backward_with_params(seed, idx, offset)
tjs = sample_trajectories(network, mutant, sample_size)
tj = tjs[idx]
for pose, t in zip(tj, ts):
    visualization.draw_point(world, (pose.x, pose.y), t, 
                            size=0.1,
                            color=carla.Color(0, 0, 255),
                            lifetime=300)
