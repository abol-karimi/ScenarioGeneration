"""
Generates random seeds using simulation.
1. A random route through the intersection is chosen for the VUT.
2. A random number of non-egos with random routes through the intersection are chosen.
3. All the vehicles (VUT and non-egos) are driven using the VUT's algorithm.
"""
import time
import random
import numpy
import jsonpickle
import hashlib
from pathlib import Path

import scenic
scenic.setDebuggingOptions(verbosity=1, fullBacktrace=True)
from scenic.core.simulators import SimulationCreationError

from scenariogen.core.errors import SplineApproximationError
from scenariogen.core.utils import seed_from_sim, ordinal


class RandomSeedGenerator:
    def __init__(self, config):
        self.config = config

    def set_state(self, state):
        random.setstate(state['rand-state'])
        numpy.random.set_state(state['np-state'])

    def get_state(self):
        return {'rand-state': random.getstate(),
                'np-state': numpy.random.get_state(),
               }
    
    def run(self):
        pass

    def runs(self, generator_state):
        if generator_state: # resume
            self.set_state(generator_state)
        else:
            random.seed(self.config['randomizer-seed'])
            numpy.random.seed(self.config['randomizer-seed'])

        start_time = time.time()
        seed_id = 0

        scenario = scenic.scenarioFromFile(
                        f"src/scenariogen/simulators/{config['simulator']}/create.scenic",
                        mode2D=True,
                        params={'render': config['render-ego'],
                                'config': config
                                },
                        )
        print('Scenario compiled successfully.')

        simulator = scenario.getSimulator()

        if not config['render-spectator']:
            settings = simulator.world.get_settings()
            settings.no_rendering_mode = True
            simulator.world.apply_settings(settings)
        
        fuzz_inputs_path = Path(config['fuzz-inputs-folder'])
        fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
        
        while time.time()-start_time < config['max-total-time']:
            try:
                scene, iterations = scenario.generate(maxIterations=config['scene-maxIterations'])
                print(f"Initial scene generated in {iterations} iteration{'(s)' if iterations > 1 else ''}.")
                
                sim_result = simulator.simulate(
                                    scene,
                                    maxSteps=scenario.params['steps'],
                                    maxIterations=config['simulate-maxIterations'],
                                    raiseGuardViolations=True
                                    )
            except SimulationCreationError as e:
                print(f'Failed to create simulation: {e}')
                continue
            else:
                if sim_result is None:
                    print(f'Simulation rejected!')
                    continue

            print('Simulation finished successfully.')
            try:           
                seed = seed_from_sim(sim_result,
                                    scenario.params['timestep'],
                                    degree=config['spline-degree'],
                                    knots_size=config['spline-knots-size']
                                    )
            except SplineApproximationError as e:
                print(e)
                continue
            else:
                # Save the new seed
                seed_json_bytes = jsonpickle.encode(seed, indent=1).encode('utf-8')
                seed_hash = hashlib.sha1(seed_json_bytes).hexdigest()
                with open(fuzz_inputs_path/seed_hash, 'wb') as f:
                    f.write(seed_json_bytes)
                seed_id += 1
                print(f'Saved the {ordinal(seed_id)} seed as {seed_hash}.')
                
                if 'coverage_module' in config and config['save-coverage-events']:
                    events = sim_result.records['events']
                    with open(Path(config['events-folder'])/seed_hash, 'w') as f:
                        f.write(jsonpickle.encode(events, indent=1))
                    
