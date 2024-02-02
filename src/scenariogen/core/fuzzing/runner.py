import multiprocessing
import traceback
from collections import namedtuple

import scenic
scenic.setDebuggingOptions(verbosity=0, fullBacktrace=True)
from scenic.domains.driving.roads import Network
from scenic.simulators.carla.simulator import CarlaSimulator
from scenic.simulators.newtonian.simulator import NewtonianSimulator

SimResult = namedtuple('SimResult', ['records'])


def simulation_service(connection,
                       carla_map,
                       map_path,
                       simulator_name,
                       timestep,
                       render_ego,
                       render_spectator):
  """Reads scenario config from connection, then writes sim_result to connection.
  Does not catch any exceptions so the daemon exits upon any exception in the service process.
  If the daemon exits, the SUTRunner.run function will spawn a new daemon upon its next execution.
  """

  if simulator_name == 'carla':
    simulator = CarlaSimulator(carla_map=carla_map,
                                map_path=map_path,
                                timestep=timestep,
                                render=render_ego)
    if not render_spectator:
      settings = simulator.world.get_settings()
      settings.no_rendering_mode = True
      simulator.world.apply_settings(settings)
  elif simulator_name == 'newtonian':
    simulator = NewtonianSimulator(network=Network.fromFile(map_path),
                                    render=render_spectator)
  # service loop
  while True:
    try:
      config = connection.recv()
    except EOFError:
      print(f'Simulation service received EOFError. Closing the service...')
      break

    # for any received simulation config, we must send a simulation result (even if None)
    sim_result = None

    try:
      render = (config['simulator'] == 'carla' and config['render-ego']) or \
                (config['simulator'] == 'newtonian' and config['render-spectator'])
      scenario = scenic.scenarioFromFile(f"src/scenariogen/simulators/{config['simulator']}/SUT.scenic",
                                        params= {'carla_map': config['carla-map'],
                                                  'map': config['map'],
                                                  'weather': config['weather'],
                                                  'timestep': config['timestep'],
                                                  'render': 1 if render else 0,
                                                  'config': config},
                                        mode2D=True)
      scene, _ = scenario.generate(maxIterations=1)
      sim_result = simulator.simulate(scene,
                                      maxSteps=config['steps'],
                                      maxIterations=1,
                                      raiseGuardViolations=True)
    except Exception as e:
      print(f'Exception of type {type(e)} in simulation service: {e}')
      traceback.print_exc()

    if sim_result:
      connection.send(SimResult(sim_result.records))
    else:
      connection.send(None)


class SUTRunner:
  server_process = None
  client_conn = None
  server_conn = None
  
  @classmethod
  def start_simulation_server(cls, carla_map, map_path, simulator_name, timestep, render_ego, render_spectator):
    if cls.server_process is not None and cls.server_process.is_alive():
      return
    ctx = multiprocessing.get_context('spawn')
    cls.client_conn, cls.server_conn = ctx.Pipe(duplex=True)
    cls.server_process = ctx.Process(target=simulation_service,
                                      name='Simulation-service daemon',
                                      args=(cls.server_conn, carla_map, map_path, simulator_name, timestep, render_ego, render_spectator),
                                      daemon=True)
    cls.server_process.start()

  @classmethod
  def run(cls, config):
    """ Runs the scenario.
    Returns the discrete-time trajectories.
    """   
    cls.start_simulation_server(config['carla-map'],
                                config['map'],
                                config['simulator'],
                                config['timestep'],
                                config['render-ego'],
                                config['render-spectator'])
    
    cls.client_conn.send(config)
    print(f'Simulating the scenario...')

    while cls.server_process.is_alive():
      if cls.client_conn.poll(10):
        sim_result = cls.client_conn.recv()
        return sim_result
    
    print(f"Simulation-service daemon exited! Closing the process and the pipe...")
    cls.server_process.close()
    cls.client_conn.close()
    cls.server_conn.close()
    
    cls.server_process = None
    cls.client_conn = None
    cls.server_conn = None

    return None


 
    