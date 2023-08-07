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

  def __init__(self, fuzz_input):
    self.fuzz_input = fuzz_input
  
  def run(self, config={}):
    """ Runs the scenario.
    Returns the discrete-time trajectories.
    """
    bps = [self.dim2bp[(int(l*100), int(w*100))][0]
       for l, w in zip(self.fuzz_input.lengths, self.fuzz_input.widths)]
    
    config = {**self.fuzz_input.config,
              **config,
              'blueprints': bps,
              'fuzz_input': self.fuzz_input,
              }
  
    # For closed-loop fuzzing, simulate the ego too.
    params = {'carla_map': config['carla_map'],
              'map': config['map'],
              'render': config['render'],
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
    scene, _ = scenic_scenario.generate(maxIterations=1)
    simulator = scenic_scenario.getSimulator()

    print(f'Simulating the scenario...')
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=config['steps'],
                    maxIterations=1,
                    raiseGuardViolations=True)

    del scenic_scenario, scene
    
    return sim_result