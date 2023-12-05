import scenic
scenic.setDebuggingOptions(verbosity=0, fullBacktrace=True)
from scenic.domains.driving.roads import Network
from scenic.simulators.carla.simulator import CarlaSimulator
from scenic.simulators.newtonian.simulator import NewtonianSimulator

class Scenario:
  simulator = None
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
              }
  
    render = (config['simulator'] == 'carla' and config['render_ego']) or \
             (config['simulator'] == 'newtonian' and config['render_spectator'])
    scenic_scenario = scenic.scenarioFromFile(
                        f"src/scenariogen/simulators/{config['simulator']}/SUT.scenic",
                        mode2D=True,
                        params= {'carla_map': config['carla_map'],
                                  'map': config['map'],
                                  'weather': config['weather'],
                                  'timestep': config['timestep'],
                                  'render': 1 if render else 0,
                                  'config': config,
                                }
                        )
    scene, _ = scenic_scenario.generate(maxIterations=1)

    if Scenario.simulator is None:
      if config['simulator'] == 'carla':
        Scenario.simulator = CarlaSimulator(
                                carla_map=config['carla_map'],
                                map_path=config['map'],
                                timestep=config['timestep'],
                                render=config['render_ego']
                                )
        if not config['render_spectator']:
          settings = Scenario.simulator.world.get_settings()
          settings.no_rendering_mode = True
          Scenario.simulator.world.apply_settings(settings)
      elif config['simulator'] == 'newtonian':
        Scenario.simulator = NewtonianSimulator(network=Network.fromFile(config['map']),
                                                render=config['render_spectator'])

    print(f'Simulating the scenario...')
    sim_result = Scenario.simulator.simulate(
                    scene,
                    maxSteps=config['steps'],
                    maxIterations=1,
                    raiseGuardViolations=True)
  
    return sim_result