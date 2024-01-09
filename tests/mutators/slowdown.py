#!/usr/bin/env python3.8

# TODO use unittest

# External libraries
import jsonpickle
import carla

# This project
from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzz_input import FuzzInput
import scenariogen.simulators.carla.visualization as visualization

# Connect to the Carla simulator
client = carla.Client('127.0.0.1', 2000)
world = client.get_world()

settings = world.get_settings()
settings.synchronous_mode = False
world.apply_settings(settings)

# Load a seed, plot its trajectory
with open('experiments/seeds_manual/0.json', 'r') as f:
    seed = jsonpickle.decode(f.read())
    assert isinstance(seed, FuzzInput)

resolution = 0.05
umin, umax = 0, seed.timings[0].ctrlpts[-1][1]
footprint, timing = seed.footprints[0], seed.timings[0]
visualization.draw_spline(world, footprint, timing, resolution, umin, umax,
                          size=0.1,
                          color=carla.Color(0, 0, 255),
                          lifetime=120)

# Speed up its trajectory over an interval, plot the new trajectory
mutator = StructureAwareMutator(max_spline_knots_size=50,
                              max_mutations_per_iteration=1,
                              randomizer_seed=0)
mutant = mutator.slowdown_with_params(seed, 0, (umin, umax/2), .9)
footprint, timing = mutant.footprints[0], mutant.timings[0]
visualization.draw_spline(world, footprint, timing, resolution, umin, umax,
                          size=0.1,
                          color=carla.Color(255, 0, 0),
                          draw_ctrlpts=True,
                          lifetime=120)