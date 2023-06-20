import scenic
from scenic.simulators.newtonian import NewtonianSimulator

class Scenario:
  def __init__(self, config):
    self.config = config
  
  def run(self):
    """ Runs the scenario.
    Returns the discrete-time trajectories.
    """
    # Sample the nonego splines.
    seconds = self.config['seed'].trajectories[0].ctrlpts[-1][2]
    
    # For closed-loop fuzzing, simulate the ego too.
    params = {'carla_map': self.corpus.config['carla_map'],
              'map': self.corpus.config['map'],
              'render': True,
              'timestep': self.config['timestep'],
              'config': self.config,
              }

    scenic_scenario = scenic.scenarioFromFile(
                        'run_seed.scenic',
                        scenario='ClosedLoop' if self.config['ego'] else 'OpenLoop',
                        params=params)
    print(f'Initializing the scenario...')
    scene, _ = scenic_scenario.generate(maxIterations=1)
    simulator = NewtonianSimulator() # TODO read the simulator type from config

    print(f'Simulating the scenario...')
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=int(seconds / self.config['timestep']),
                    maxIterations=1,
                    raiseGuardViolations=True)

    del scenic_scenario, scene
    
    return sim_result