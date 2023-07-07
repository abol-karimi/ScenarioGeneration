#!/usr/bin/env python3.8

# Standard libraries
import argparse
import jsonpickle, pickle
from pathlib import Path
import numpy as np
from geomdl import knotvector

# Scenic modules
import scenic
from scenic.simulators.newtonian import NewtonianSimulator
from scenic.core.simulators import SimulationCreationError
from scenic.core.dynamics import GuardViolation


# My modules
from scenariogen.core.seed import Seed, Spline
from scenariogen.core.utils import sim_trajectories, spline_approximation

#----------Main Script----------
parser = argparse.ArgumentParser(description='Make a seed from a scenic scenario.')
parser.add_argument('scenario_path', 
                    help='Path of the Scenic file specifying the scenario')
parser.add_argument('--simulator', choices=['newtonian', 'carla'], default='newtonian',
                    help='The simulator')
parser.add_argument('--out_path',
                    help='Path where the generated seed will be stored')
parser.add_argument('--save_sim_trajectories', action='store_true',
                    help="""Save the simulated trajectories for debugging.
                            Note that each trajectory saved in the seed is a spline approximation of the simulated counterpart.""")
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

simulator2model = {'newtonian': 'scenic.simulators.newtonian.driving_model',
                    'carla': 'scenic.simulators.carla.model'
                    }
# Run the scenario
scenic_scenario = scenic.scenarioFromFile(
    args.scenario_path,
    model=simulator2model[args.simulator],
    params = {'timestep': args.timestep})
scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = scenic_scenario.getSimulator()
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
sim_trajs = sim_trajectories(sim_result, args.timestep)

positions = tuple(spline_approximation(traj,
                                    degree=args.spline_degree,
                                    knots_size=args.parameters_size)
                    for traj in sim_trajs)
timing = Spline(degree=args.spline_degree,
                ctrlpts=tuple((float(t), float(t)) for t in np.linspace(0, seconds, args.parameters_size)),
                knotvector=tuple(float(t*seconds) for t in knotvector.generate(args.spline_degree, args.parameters_size, clamped=True))
                )
seed = Seed(config=config,
            routes=routes,
            positions=positions,
            timings=(timing,)*len(sim_trajs),
            signals=signals,
            lengths=lengths,
            widths=widths)

# Store the seed
if args.out_path:
    with open(args.out_path, 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))    
else:
    scenario_path = Path(args.scenario_path)
    with open(scenario_path.parents[1]/'initial_seeds'/f'{scenario_path.stem}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))

# Save the simulated trajectories for debugging
if args.save_sim_trajectories:
    with open(scenario_path.with_name(f'{scenario_path.stem}_sim_trajectories.pickle'), 'wb') as f:
        pickle.dump(sim_trajs, f)