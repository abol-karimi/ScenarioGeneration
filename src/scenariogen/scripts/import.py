#!/usr/bin/env python3

# Standard libraries
import argparse
import jsonpickle
from pathlib import Path

# Scenic modules
import scenic
scenic.setDebuggingOptions(verbosity=0, fullBacktrace=True)
from scenic.core.simulators import SimulationCreationError

# My modules
from scenariogen.core.utils import seed_from_sim
from scenariogen.core.errors import NonegoCollisionError

#----------Main Script----------
parser = argparse.ArgumentParser(description='Make a seed from a scenic scenario.')
parser.add_argument('complexgen_scenario_path',
                    help='Path of the ComplexGen scenario file (in json format)')
parser.add_argument('--simulator', choices=['newtonian', 'carla'], default='carla',
                    help='The simulator')
parser.add_argument('--render-spectator', action='store_true',
                    help='render a spectator above the intersection')
parser.add_argument('--render-ego', action='store_true',
                    help='render ego viewpoint (only in the Carla simulator)')
parser.add_argument('--out_path',
                    help='Path where the generated seed will be stored')
parser.add_argument('--spline-degree', default = 3, type=int)
args = parser.parse_args()

# Run the scenario
scenic_scenario = scenic.scenarioFromFile(
                    f'src/scenariogen/simulators/{args.simulator}/create.scenic',
                    mode2D=True,
                    params = {'caller_config':{'scenario-file': 'src/scenariogen/interfaces/complexgen/import.scenic',
                                               'complexgen_scenario_path': args.complexgen_scenario_path,
                                               'render-spectator': args.render_spectator,
                                               'render-ego': args.render_ego,
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
                    maxSteps=scenic_scenario.params['steps'],
                    maxIterations=1,
                    raiseGuardViolations=True
                    )
    if sim_result is None:
        raise RuntimeError('Simulation rejected.')
except NonegoCollisionError as err:
    raise RuntimeError(f'Collision between nonego {err.nonego} and actor {err.other}, discarding the simulation.')
except SimulationCreationError:
    raise RuntimeError('Failed to create scenario.')
else:
    # Save the seed
    scenario_path = Path(args.complexgen_scenario_path)
    seed = seed_from_sim(sim_result,
                        scenic_scenario.params['timestep'],
                        degree=args.spline_degree)
    if args.out_path:
        with open(args.out_path, 'w') as f:
            f.write(jsonpickle.encode(seed, indent=1))
    else:
        with open(f'experiments/seeds/complex/seeds/{scenario_path.stem}.json', 'w') as f:
            f.write(jsonpickle.encode(seed, indent=1))
