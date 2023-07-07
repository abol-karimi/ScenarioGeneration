#!/usr/bin/env python3.8

# External libraries
import jsonpickle
import carla

# This project
from src.scenariogen.core.mutators import RandomMutator
from scenariogen.core.seed import Seed
import scenariogen.simulators.carla.visualization as visualization

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

resolution = 0.05
interval = (0, seed.trajectories[0].ctrlpts[-1][2])
spline = seed.trajectories[0]
visualization.draw_spline(world, spline, resolution, interval,
                          size=0.1,
                          color=carla.Color(0, 0, 255),
                          lifetime=120)

# Speed up its trajectory over an interval, plot the new trajectory
mutator = RandomMutator(max_parameters_size=50,
                              max_mutations_per_iteration=1,
                              randomizer_seed=0)
mutant = mutator.speedup_with_params(seed, 0, (0, 10), 0.9)
spline = mutant.trajectories[0]
visualization.draw_spline(world, spline, resolution, interval,
                          size=0.1,
                          color=carla.Color(255, 0, 0),
                          lifetime=120)