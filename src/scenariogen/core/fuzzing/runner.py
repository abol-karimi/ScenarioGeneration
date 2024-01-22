from multiprocessing import Process, Pipe
import traceback
import jsonpickle
from collections import namedtuple

import scenic
scenic.setDebuggingOptions(verbosity=0, fullBacktrace=True)
from scenic.domains.driving.roads import Network
from scenic.simulators.carla.simulator import CarlaSimulator
from scenic.simulators.newtonian.simulator import NewtonianSimulator

SimResult = namedtuple('SimResult', ['records'])

class Runner:
  service_process = None
  client_conn = None
  server_conn = None

  @classmethod
  def simulation_service(cls, connection, config):
    """Reads scenario config from connection, then writes sim_result to connection."""

    if config['simulator'] == 'carla':
      simulator = CarlaSimulator(carla_map=config['carla_map'],
                                 map_path=config['map'],
                                 timestep=config['timestep'],
                                 render=config['render-ego'])
      if not config['render-spectator']:
        settings = simulator.world.get_settings()
        settings.no_rendering_mode = True
        simulator.world.apply_settings(settings)
    elif config['simulator'] == 'newtonian':
      simulator = NewtonianSimulator(network=Network.fromFile(config['map']),
                                              render=config['render-spectator'])
    # service loop
    while True:
      config = connection.recv()    
      render = (config['simulator'] == 'carla' and config['render-ego']) or \
              (config['simulator'] == 'newtonian' and config['render-spectator'])
      scenario = scenic.scenarioFromFile(f"src/scenariogen/simulators/{config['simulator']}/SUT.scenic",
                                        params= {'carla_map': config['carla_map'],
                                                 'map': config['map'],
                                                 'weather': config['weather'],
                                                 'timestep': config['timestep'],
                                                 'render': 1 if render else 0,
                                                 'config': config},
                                        mode2D=True)
      sim_result = None
      try:
        scene, _ = scenario.generate(maxIterations=1)
        sim_result = simulator.simulate(scene,
                                        maxSteps=config['steps'],
                                        maxIterations=1,
                                        raiseGuardViolations=True)
      except Exception as e:
        print(f'Exception of type {type(e)} when simulating the scenario (in simulate-SUT daemon): {e}')
        traceback.print_exc()

      if sim_result:
        connection.send(SimResult(sim_result.records))
      else:
        connection.send(None)

  @classmethod
  def run(cls, config):
    """ Runs the scenario.
    Returns the discrete-time trajectories.
    """

    if cls.service_process is None or not cls.service_process.is_alive():
      cls.client_conn, cls.server_conn = Pipe(duplex=True)
      cls.service_process = Process(target=cls.simulation_service,
                                     name='Simulation-service daemon',
                                     args=(cls.server_conn, config),
                                     daemon=True
                                    )
      cls.service_process.start()
    
    cls.client_conn.send(config)
    print(f'Simulating the scenario...')

    while cls.service_process.is_alive():
      if cls.client_conn.poll(10):
        sim_result = cls.client_conn.recv()
        return sim_result
    
    print(f"Simulation-service daemon exited! Closing the process and the pipe...")
    cls.service_process.close()
    cls.client_conn.close()
    cls.server_conn.close()
    
    cls.service_process = None
    cls.client_conn = None
    cls.server_conn = None

    return None


 
    