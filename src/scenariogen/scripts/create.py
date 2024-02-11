#!/usr/bin/env python3.8

# Standard libraries
import argparse
import jsonpickle
from pathlib import Path
from queue import Queue

# Scenic modules
import scenic
scenic.setDebuggingOptions(verbosity=0, fullBacktrace=True)
from scenic.core.simulators import SimulationCreationError

from scenariogen.core.utils import seed_from_sim
from scenariogen.core.fuzzing.runner import run_callbacks


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Make a seed from a scenic scenario.')
  parser.add_argument('scenario_file',
                      help='Path of the Scenic file specifying the scenario')
  parser.add_argument('--simulator', choices=['newtonian', 'carla'], default='carla',
                      help='The simulator')
  parser.add_argument('--render-spectator', action='store_true',
                      help='render a spectator above the intersection')
  parser.add_argument('--render-ego', action='store_true',
                      help='render ego viewpoint (only in the Carla simulator)')
  parser.add_argument('--seed-file',
                      help='Path where the generated seed will be stored')
  parser.add_argument('--spline-degree', default = 3, type=int)
  args = parser.parse_args()

  # Run the scenario
  cleanup_callbacks = Queue()
  scenic_scenario = scenic.scenarioFromFile(
                      f'src/scenariogen/simulators/{args.simulator}/create.scenic',
                      mode2D=True,
                      params = {'config':{'scenario-file': args.scenario_file,
                                          'render-spectator': args.render_spectator,
                                          'render-ego': args.render_ego,
                                          },
                                'cleanup_callbacks': cleanup_callbacks
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
                    maxIterations=1)
  except SimulationCreationError as e:
    print(f'Failed to create simulation: {e}')
  else:
    run_callbacks(cleanup_callbacks)
    
    if sim_result is None:
      print('Simulation rejected.')
      exit(1)
    
    # Save the seed
    scenario_file = Path(args.scenario_file)
    seed = seed_from_sim(sim_result,
                         scenic_scenario.params['timestep'],
                         degree=args.spline_degree)
    if args.seed_file:
      with open(args.seed_file, 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))
    else:
      with open(scenario_file.parents[1]/'seeds'/f'{scenario_file.stem}.json', 'w') as f:
        f.write(jsonpickle.encode(seed, indent=1))
