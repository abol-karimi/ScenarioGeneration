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
parser.add_argument('--simulator', choices=['newtonian', 'carla'], default='newtonian',
                    help='The simulator')
parser.add_argument('--render_spectator', action='store_true',
                    help='render a spectator above the intersection')
parser.add_argument('--render_ego', action='store_true',
                    help='render ego viewpoint (only in the Carla simulator)')
parser.add_argument('--out_path',
                    help='Path where the generated seed will be stored')
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

# Run the scenario
scenic_scenario = scenic.scenarioFromFile(
                    'src/scenariogen/core/create.scenic',
                    mode2D=True,
                    params = {'timestep': args.timestep,
                              'caller_config':{'scenario_path': args.scenario_path,
                                               'simulator_name': args.simulator,
                                               'steps': steps,
                                               'render_spectator': args.render_spectator,
                                               'render_ego': args.render_ego,
                                               }
                              }
                    )
scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = scenic_scenario.getSimulator()
if args.simulator == 'carla' and not args.render_spectator:
    settings = simulator.world.get_settings()
    settings.no_rendering_mode = True
    simulator.world.apply_settings(settings)

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
    with open(scenario_path.parents[1]/'seeds_manual'/f'{scenario_path.stem}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))
