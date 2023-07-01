#!/usr/bin/env python3.8

# Standard libraries
import argparse
import jsonpickle, pickle
from pathlib import Path

# Scenic modules
import scenic
from scenic.simulators.newtonian import NewtonianSimulator
from scenic.core.simulators import SimulationCreationError
from scenic.core.dynamics import GuardViolation


# My modules
from scenariogen.core.seed import Seed
from scenariogen.core.utils import spacetime_trajectories, spline_approximation

#----------Main Script----------
parser = argparse.ArgumentParser(description='Make a seed from a scenic scenario.')
parser.add_argument('scenic_file', 
                    help='Path of the Scenic file specifying the scenario')
duration = parser.add_mutually_exclusive_group()
duration.add_argument('--steps', type=int,
                      help='The duration of the scenario in steps')
duration.add_argument('--seconds', type=float,
                      help='The duration of the scenario in seconds')
parser.add_argument('--timestep', default=0.05, type=float, 
                    help='The length of one simulation step')
parser.add_argument('--spline_degree', default = 3, type=int)
parser.add_argument('--parameters_size', default = 50, type=int)
args = parser.parse_args()

# Default duration:
seconds = 20
# Override with custom duration:
if args.steps:
    seconds = args.steps * args.timestep
elif args.seconds:
    seconds = args.seconds
steps = seconds // args.timestep

# Run the scenario
scenic_scenario = scenic.scenarioFromFile(
    args.scenic_file,
    params = {'timestep': args.timestep})
scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = NewtonianSimulator()
try:
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=steps,
                    maxIterations=1,
                    raiseGuardViolations=True
                    )
except SimulationCreationError:
    print('Failed to create scenario.')
    exit()
except GuardViolation:
    print('Guard violated in simulation.')
    exit()

# Convert the result to a seed
routes = sim_result.records['routes']
signals = sim_result.records['turn_signals']
lengths = sim_result.records['lengths']
widths = sim_result.records['widths']
config = sim_result.records['config']
spacetime_trajs = spacetime_trajectories(sim_result, args.timestep)

# Save the simulated trajectories for debugging
with open('spacetime_trajectories.pickle', 'wb') as outFile:
    pickle.dump(spacetime_trajs, outFile)

trajectories = tuple(spline_approximation
                            (traj,
                            degree=args.spline_degree,
                            knots_size=args.parameters_size)
                    for traj in spacetime_trajs)
seed = Seed(config=config,
            routes=routes,
            trajectories=trajectories,
            signals=signals,
            lengths=lengths,
            widths=widths)

# Store the seed
scenic_path = Path(args.scenic_file)
with open(scenic_path.with_name(scenic_path.stem + '.json'), 'w') as f:
    f.write(jsonpickle.encode(seed, indent=1))
