import jsonpickle
import scenic

class Scenario:
  # Choose a blueprint of an appropriate size for each non-ego
  def __init__(self, fuzz_input):
    self.fuzz_input = fuzz_input
  
  def run(self, config={}):
    """ Runs the scenario.
    Returns the discrete-time trajectories.
    """
    config = {**self.fuzz_input.config,
              **config,
              'fuzz_input': self.fuzz_input,
              }
  
    simulator2model = {'newtonian': 'scenic.simulators.newtonian.driving_model',
                       'carla': 'scenic.simulators.carla.model'
                      }
    scenic_scenario = scenic.scenarioFromFile(
                        'src/scenariogen/core/SUT.scenic',
                        mode2D=True,
                        model=simulator2model[config['simulator']],
                        params= {'carla_map': config['carla_map'],
                                  'map': config['map'],
                                  'render': config['render'],
                                  'timestep': config['timestep'],
                                  'config': config,
                                }
                        )
    scene, _ = scenic_scenario.generate(maxIterations=1)
    simulator = scenic_scenario.getSimulator()

    print(f'Simulating the scenario...')
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=config['steps'],
                    maxIterations=1,
                    raiseGuardViolations=True)
  
    return sim_result