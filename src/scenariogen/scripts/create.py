#!/usr/bin/env python3.8

# Standard libraries
import argparse
import jsonpickle, pickle
from pathlib import Path

# Scenic modules
import scenic
from scenic.core.simulators import SimulationCreationError
from scenic.core.dynamics import GuardViolation


# My modules
from scenariogen.core.utils import sim_trajectories, seed_from_sim
from scenariogen.core.errors import NonegoNonegoCollisionError

#----------Main Script----------
parser = argparse.ArgumentParser(description='Make a seed from a scenic scenario.')
parser.add_argument('scenario_path', 
                    help='Path of the Scenic file specifying the scenario')
parser.add_argument('--simulator', choices=['newtonian', 'carla'], default='carla',
                    help='The simulator')
parser.add_argument('--no_render', action='store_true',
                    help='disable rendering')
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
parser.add_argument('--spline_knots_size', default = 50, type=int)
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
                    'src/scenariogen/scripts/create.scenic',
                    mode2D=True,
                    model=simulator2model[args.simulator],
                    params = {'timestep': args.timestep,
                              'simulator': args.simulator,
                              'render': not args.no_render,
                              'scenario_path': args.scenario_path,
                              'save_sim_trajectories': args.save_sim_trajectories,
                              'caller_config':{'steps': steps}
                              }
                    )
scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = scenic_scenario.getSimulator()
try:
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=steps,
                    maxIterations=1,
                    raiseGuardViolations=True
                    )
except NonegoNonegoCollisionError as err:
    print(f'Collision between nonegos {err.nonego} and {err.other}, discarding the simulation.')
    exit()
except SimulationCreationError:
    print('Failed to create scenario.')
    exit()
except GuardViolation:
    print('Guard violated in simulation.')
    exit()

# Save the seed
scenario_path = Path(args.scenario_path)
seed = seed_from_sim(sim_result,
                     args.timestep,
                     degree=args.spline_degree,
                     knots_size=args.spline_knots_size)
if args.out_path:
    with open(args.out_path, 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))
else:
    with open(scenario_path.parents[1]/'seeds'/f'{scenario_path.stem}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))

# Save the simulated trajectories for debugging
if args.save_sim_trajectories:
    sim_trajs = sim_trajectories(sim_result, args.timestep)
    with open(scenario_path.with_name(f'{scenario_path.stem}_sim_trajectories.pickle'), 'wb') as f:
        pickle.dump(sim_trajs, f)