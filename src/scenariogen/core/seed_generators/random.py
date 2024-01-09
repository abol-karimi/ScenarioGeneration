"""
Generates random seeds using simulation.
1. A random route through the intersection is chosen for the VUT.
2. A random number of non-egos with random routes through the intersection are chosen.
3. All the vehicles (VUT and non-egos) are driven using the VUT's algorithm.
"""
import time
import random
import jsonpickle
import hashlib
from pathlib import Path

import scenic
scenic.setDebuggingOptions(verbosity=1, fullBacktrace=True)
from scenic.core.simulators import SimulationCreationError

from scenariogen.core.errors import EgoCollisionError, SplineApproximationError
from scenariogen.core.utils import seed_from_sim, ordinal
from scenariogen.core.coverages.coverage import StatementCoverage, PredicateSetCoverage, PredicateCoverage


coverages_statements = StatementCoverage([])
coverages_predicateSet = PredicateSetCoverage([])
coverages_predicates = PredicateCoverage([])


def run(config):
    start_time = time.time()
    random.seed(config['PRNG_seed'])
    seed_id = 0

    scenario = scenic.scenarioFromFile(
                    f"src/scenariogen/simulators/{config['simulator']}/create.scenic",
                    mode2D=True,
                    params={'render': config['render_ego'],
                            'config': config
                            },
                    )
    print('Scenario compiled successfully.')

    simulator = scenario.getSimulator()

    if not config['render_spectator']:
        settings = simulator.world.get_settings()
        settings.no_rendering_mode = True
        simulator.world.apply_settings(settings)
    
    output_path = Path(config['output_folder'])
    output_path.mkdir(parents=True, exist_ok=True)
       
    while time.time()-start_time < config['max_total_time']:
        try:
            scene, iterations = scenario.generate(maxIterations=config['scene_maxIterations'])
            print(f"Initial scene generated in {iterations} iteration{'(s)' if iterations > 1 else ''}.")
            
            sim_result = simulator.simulate(
                                scene,
                                maxSteps=scenario.params['steps'],
                                maxIterations=config['simulate_maxIterations'],
                                raiseGuardViolations=True
                                )
        except EgoCollisionError as err:
            print(f'Ego collided with {err.other}, discarding the seed.')
            continue
        except SimulationCreationError as e:
            print(f'Failed to create simulation: {e}')
            continue
        # except Exception as e:
        #     print(f'Exception of type {type(e)}: {e}. Discarding the simulation...')
        #     continue
        else:
            if sim_result is None:
                print(f'Simulation rejected!')
                continue

        print('Simulation finished successfully.')
        try:           
            seed = seed_from_sim(sim_result,
                                 scenario.params['timestep'],
                                 degree=config['spline_degree'],
                                 knots_size=config['spline_knots_size']
                                )
        except SplineApproximationError as e:
            print(e)
            continue
        else:
            coverage_statements = sim_result.records['coverage']
            if coverage_statements is None:
                continue

            coverage_predicateSet = coverage_statements.cast_to(PredicateSetCoverage)
            coverage_predicates = coverage_statements.cast_to(PredicateCoverage)
            if len(coverage_statements - coverages_statements) > 0 \
                or len(coverage_predicates - coverages_predicates) > 0 \
                or len(coverage_predicateSet - coverages_predicateSet) > 0:

                # Update total coverages seen
                coverages_statements.update(coverage_statements)
                coverages_predicateSet.update(coverage_predicateSet)
                coverages_predicates.update(coverage_predicates)

                # Save the new seed and its coverage
                seed_json_bytes = jsonpickle.encode(seed, indent=1).encode('utf-8')
                seed_hash = hashlib.sha1(seed_json_bytes).hexdigest()
                with open(output_path/f'fuzz-inputs/{seed_hash}', 'wb') as f:
                    f.write(seed_json_bytes)
                with open(output_path/f'coverages/{seed_hash}', 'w') as f:
                    f.write(jsonpickle.encode(coverage_statements, indent=1))
                seed_id += 1
                print(f'Saved the {ordinal(seed_id)} seed as {seed_hash}.')





        

            
                
