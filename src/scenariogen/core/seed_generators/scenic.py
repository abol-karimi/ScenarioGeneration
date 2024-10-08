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
from pathlib import Path

import scenic
scenic.setDebuggingOptions(verbosity=1, fullBacktrace=True)
from scenic.core.simulators import SimulationCreationError

from scenariogen.core.errors import SplineApproximationError
from scenariogen.core.utils import seed_from_sim, ordinal


class RandomSeedGenerator:
  def __init__(self, config):
    self.config = config
    self.seed_id = 0

  def set_state(self, state):
    random.setstate(state['rand-state'])
    numpy.random.set_state(state['np-state'])
    self.seed_id = state['seed-id']

  def get_state(self):
    return {'rand-state': random.getstate(),
            'np-state': numpy.random.get_state(),
            'seed-id': self.seed_id,
            }

  def run(self, scenario, simulator):
    try:
      scene, iterations = scenario.generate(maxIterations=self.config['scene-maxIterations'])
      print(f"Initial scene generated in {iterations} iteration{'(s)' if iterations > 1 else ''}.")
      
      sim_result = simulator.simulate(scene,
                                      maxSteps=scenario.params['steps'],
                                      maxIterations=self.config['simulate-maxIterations'],
                                      raiseGuardViolations=True
                                      )
    except SimulationCreationError as e:
      print(f'Failed to create simulation: {e}')
      return
    else:
      if sim_result is None:
        print(f'Simulation rejected!')
        return
      else:
        print('Simulation finished successfully.')

    try:
      seed = seed_from_sim(sim_result,
                          scenario.params['timestep'],
                          degree=self.config['spline-degree'])
    except SplineApproximationError as e:
      print(e)
      return
    else:
      # Save the new seed
      with open(Path(self.config['fuzz-inputs-folder'])/f'{seed.hexdigest}.json', 'wb') as f:
          f.write(seed.bytes)
      self.seed_id += 1
      print(f'Saved the {ordinal(self.seed_id)} seed as {seed.hexdigest}.')
      
      if 'coverage-config' in self.config and self.config['save-coverage-events']:
        events = sim_result.records['events']
        with open(Path(self.config['events-folder'])/f'{seed.hexdigest}.json', 'w') as f:
            f.write(jsonpickle.encode(events, indent=1))

  def runs(self, generator_state):
    if generator_state: # resume
      self.set_state(generator_state)
    else:
      random.seed(self.config['randomizer-seed'])
      numpy.random.seed(self.config['randomizer-seed'])
    start_time = time.time()
    scenario = scenic.scenarioFromFile(
                f"src/scenariogen/simulators/{self.config['SUT-config']['simulator']}/create.scenic",
                mode2D=True,
                params={'render': self.config['SUT-config']['render-ego'],
                        'config': {**self.config['SUT-config'],
                                   **self.config['coverage-config'],
                                   }
                        },
                )
    print('Scenario compiled successfully.')
    simulator = scenario.getSimulator()
    if not self.config['SUT-config']['render-spectator']:
      settings = simulator.world.get_settings()
      settings.no_rendering_mode = True
      simulator.world.apply_settings(settings)
  
    fuzz_inputs_path = Path(self.config['fuzz-inputs-folder'])
    fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
    
    while time.time()-start_time < self.config['max-total-time']:
       self.run(scenario, simulator)
