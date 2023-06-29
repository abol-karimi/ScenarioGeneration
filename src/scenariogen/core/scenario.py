import jsonpickle
import scenic

class Scenario:
  # Choose a blueprint of an appropriate size for each non-ego
  with open('src/scenariogen/simulators/carla/blueprint_library.json', 'r') as f:
      blueprints = jsonpickle.decode(f.read())
  dim2bp = {}
  for b, dims in blueprints.items():
      length = int(100*dims['length'])
      width = int(100*dims['width'])
      if not (length, width) in dim2bp:
          dim2bp[(length, width)] = [b]
      else:
          dim2bp[(length, width)].append(b)

  def __init__(self, seed):
    self.seed = seed
  
  def run(self, config={}):
    """ Runs the scenario.
    Returns the discrete-time trajectories.
    """
    bps = [self.dim2bp[(int(l*100), int(w*100))][0]
       for l, w in zip(self.seed.lengths, self.seed.widths)]
    
    config = {**self.seed.config, **config, 'blueprints': bps}

    # Sample the nonego splines.
    seconds = self.seed.trajectories[0].ctrlpts[-1][2]
    
    # For closed-loop fuzzing, simulate the ego too.
    params = {'carla_map': config['carla_map'],
              'map': config['map'],
              'render': True,
              'timestep': config['timestep'],
              'config': config,
              }

    simulator2model = {'newtonian': 'scenic.simulators.newtonian.driving_model',
                       'carla': 'scenic.simulators.carla.model'
                      }
    scenic_scenario = scenic.scenarioFromFile(
                        'src/scenariogen/core/SUT.scenic',
                        model=simulator2model[config['simulator']],
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