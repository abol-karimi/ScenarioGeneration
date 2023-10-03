import scenic
scenic.setDebuggingOptions(verbosity=2, fullBacktrace=True)

class Scenario:
  # Choose a blueprint of an appropriate size for each non-ego
  def __init__(self, fuzz_input):
    self.fuzz_input = fuzz_input
  
  def run(self, _config={}):
    """ Runs the scenario.
    Returns the discrete-time trajectories.
    """
    config = {**self.fuzz_input.config,
              **_config,
              'fuzz_input': self.fuzz_input,
              'simulator': _config['simulator'] if 'simulator' in _config else self.fuzz_input.config['compatible_simulators'][0]
              }
  
    simulator2model = {'newtonian': 'scenic.simulators.newtonian.driving_model',
                       'carla': 'scenic.simulators.carla.model'
                      }
    render = (config['simulator'] == 'carla' and config['render_ego']) or \
             (config['simulator'] == 'newtonian' and config['render_spectator'])
    render = 1 if render else 0
    scenic_scenario = scenic.scenarioFromFile(
                        'src/scenariogen/core/SUT.scenic',
                        mode2D=True,
                        model=simulator2model[config['simulator']],
                        params= {'carla_map': config['carla_map'],
                                  'map': config['map'],
                                  'timestep': config['timestep'],
                                  'render': render,
                                  'config': config,
                                }
                        )
    scene, _ = scenic_scenario.generate(maxIterations=1)
    simulator = scenic_scenario.getSimulator()
    if config['simulator'] == 'carla' and not config['render_spectator']:
        settings = simulator.world.get_settings()
        settings.no_rendering_mode = True
        simulator.world.apply_settings(settings)
    print(f'Simulating the scenario...')
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=config['steps'],
                    maxIterations=1,
                    raiseGuardViolations=True)
  
    return sim_result