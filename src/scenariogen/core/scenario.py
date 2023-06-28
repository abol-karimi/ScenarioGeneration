import scenic

class Scenario:
  def __init__(self, seed):
    self.seed = seed
  
  def run(self, config={}):
    """ Runs the scenario.
    Returns the discrete-time trajectories.
    """
    config = {**self.seed.config, **config}

    # Sample the nonego splines.
    seconds = self.seed.trajectories[0].ctrlpts[-1][2]
    
    # For closed-loop fuzzing, simulate the ego too.
    params = {'carla_map': config['carla_map'],
              'map': config['map'],
              'render': True,
              'timestep': config['timestep'],
              'config': config,
              }

    scenic_scenario = scenic.scenarioFromFile(
                        f"{config['simulator']}/SUT.scenic",
                        scenario='ClosedLoop' if config['ego'] else 'OpenLoop',
                        params=params)
    print(f'Initializing the scenario...')
    scene, _ = scenic_scenario.generate(maxIterations=1)
    simulator = scenic_scenario.getSimulator()

    print(f'Simulating the scenario...')
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=int(seconds / config['timestep']),
                    maxIterations=1,
                    raiseGuardViolations=True)

    del scenic_scenario, scene
    
    return sim_result