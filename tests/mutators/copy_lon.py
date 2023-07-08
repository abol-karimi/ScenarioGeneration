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
umin, umax = 0, seed.timings[0].ctrlpts[-1][1]
position, timing = seed.positions[0], seed.timings[0]
visualization.draw_spline(world, position, timing, resolution, umin, umax,
                          size=0.1,
                          color=carla.Color(0, 0, 255),
                          lifetime=600)

# Copy the trajectory with a longitudinal offset, then plot the new trajectory
mutator = RandomMutator(max_parameters_size=50,
                        max_mutations_per_iteration=1,
                        randomizer_seed=0)
mutant = mutator.copy_lon_with_params(seed, 0, 100)
position, timing = mutant.positions[-1], mutant.timings[-1]
visualization.draw_spline(world, position, timing, resolution, umin, umax,
                          size=0.1,
                          color=carla.Color(255, 0, 0),
                          lifetime=600)