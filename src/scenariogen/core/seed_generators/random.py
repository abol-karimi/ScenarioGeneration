"""
Generates random seeds using simulation.
1. A random route through the intersection is chosen for the VUT.
2. A random number of non-egos with random routes through the intersection are chosen.
3. All the vehicles (VUT and non-egos) are driven using the VUT's algorithm.
"""
import random
import jsonpickle
import scenic
import scenic.core.errors as _errors
_errors.showInternalBacktrace = True   # see comment in errors module
del _errors
from scenic.core.simulators import SimulationCreationError
from scenic.core.dynamics import GuardViolation

from scenariogen.core.errors import EgoCollisionError, NonegoNonegoCollisionError
from scenariogen.core.utils import seed_from_sim

def run(config):
    random.seed(config['prng_seed'])
    seed_id = 0

    while seed_id < config['seeds_num']:
        scenario = scenic.scenarioFromFile(
                        'src/scenariogen/scripts/create.scenic',
                        params={'timestep': config['timestep'],
                                'render': config['render'],
                                'scenario_path': config['scenario_path']
                                },
                        )
        try:
            scene, iterations = scenario.generate(maxIterations=config['scene_maxIterations'])
            print(f"Scene created in {iterations} iteration{'(s)' if iterations > 1 else ''}.")
            sim_result = scenario.getSimulator().simulate(
                                scene,
                                maxSteps=config['steps'],
                                maxIterations=config['simulate_maxIterations'],
                                raiseGuardViolations=True
                                )
        except NonegoNonegoCollisionError as err:
            print(f'Collision between nonegos {err.nonego} and {err.other}, discarding the simulation.')
            continue
        except SimulationCreationError as e:
            print(f'Failed to create simulation: {e}')
            continue
        except GuardViolation as e:
            print(f'Guard violated in simulation: {e}')
            continue
        except Exception as e:
            print(f'Unhandled exception: {e} !!!')
        else:
            seed_id += 1
            print(f'Saving seed {seed_id} ...')
            seed = seed_from_sim(sim_result,
                                 config['timestep'],
                                 degree=config['spline_degree'],
                                 knots_size=config['spline_knots_size']
                                )
            with open(f"{config['output_folder']}/{seed_id}.json", 'w') as f:
                f.write(jsonpickle.encode(seed, indent=1))
        

            
                
