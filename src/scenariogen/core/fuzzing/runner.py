import multiprocessing
import traceback
from collections import namedtuple
import subprocess
import time

import scenic
scenic.setDebuggingOptions(verbosity=0, fullBacktrace=True)
from scenic.domains.driving.roads import Network
from scenic.simulators.carla.simulator import CarlaSimulator
from scenic.simulators.newtonian.simulator import NewtonianSimulator

from scenariogen.core.utils import ordinal

SimResult = namedtuple('SimResult', ['records'])


def simulation_service(connection):
  """Reads scenario config from connection, then writes sim_result to connection.
  Runs as a separate process to isolate the main process from crashes in Scenic, VUT, or Carla.
  """
  carla_server_process = None
  simulator = None

  # service loop
  while True:
    try:
      config = connection.recv()
    except EOFError:
      print(f'Client closed the connection. Ending the simulation service...')
      break

    # For any received simulation config, we must send a simulation result (even if the result is None).
    # In case of a simulator crash (e.g. Carla segmentation fault), the service restarts the simulator and tries again.
    # In case of a service crash, the client is informed by calling is_alive. Then the client restarts the service and resends the request.
    while True:
      try:
        scenario = scenic.scenarioFromFile(f"src/scenariogen/simulators/{config['simulator']}/SUT.scenic",
                                          params= {'map': config['map'],
                                                   'weather': config['weather'],
                                                   'config': config},
                                          mode2D=True)
        scene, _ = scenario.generate(maxIterations=1)
      except Exception as e:
        print(f'Failed to create the initial scene due to exception {e}.')
        connection.send(None)
        break

      try:
        if simulator is None and config['simulator'] == 'newtonian':
          simulator = NewtonianSimulator(network=Network.fromFile(config['map']),
                                          render=config['render-spectator'])
        elif config['simulator'] == 'carla':
          if (not carla_server_process is None) and not carla_server_process.poll() is None:
            print(f'Carla server exited with return code {carla_server_process.returncode}')
            carla_server_process = None

          if carla_server_process is None:
            print('Starting the Carla server...')
            render_option = '' if config['render-spectator'] or config['render-ego'] else '-RenderOffScreen'
            carla_server_process = subprocess.Popen(f"/home/carla/CarlaUE4.sh {render_option}",
                                                    shell=True)         
          if simulator is None:
            simulator = CarlaSimulator(carla_map=config['carla-map'],
                                       map_path=config['map'],
                                       timestep=config['timestep'],
                                       render=config['render-ego'])
            if not config['render-spectator']:
              settings = simulator.world.get_settings()
              settings.no_rendering_mode = True
              simulator.world.apply_settings(settings)

        sim_result = simulator.simulate(scene,
                                        maxSteps=config['steps'],
                                        maxIterations=1)
      except Exception as e:
        print(f'Failed to simulate the scenario due to exception {e}. Will try again...')
      else:
        if sim_result:
          connection.send(SimResult(sim_result.records))
        else:
          connection.send(None)
        # simulation request fulfilled
        break


class SUTRunner:
  ctx = multiprocessing.get_context('spawn')
  client_conn, server_conn = ctx.Pipe(duplex=True)
  server_process = None
  crashes = 0
 
  @classmethod
  def run(cls, config):
    """ Runs the scenario.
    Keeps retrying if the simulation server process exits with an error.
    """

    while True:
      try:
        if cls.server_process is None:
          print(f"Starting the simulation-service daemon...")
          cls.server_process = cls.ctx.Process(target=simulation_service,
                                               name='Simulation-service daemon',
                                               args=(cls.server_conn,),
                                               daemon=True)
          cls.server_process.start()
        elif not cls.server_process.is_alive():
          cls.crashes += 1
          print(f"Simulation-service daemon crashed for the {ordinal(cls.crashes)} time! Restarting the daemon...")
          cls.server_process.close()
          cls.client_conn.close()
          cls.server_conn.close()      
          cls.client_conn, cls.server_conn = cls.ctx.Pipe(duplex=True)
          cls.server_process = cls.ctx.Process(target=simulation_service,
                                               name='Simulation-service daemon',
                                               args=(cls.server_conn,),
                                               daemon=True)
          cls.server_process.start()
        
        print('Sending a request to the simulation-service daemon...')
        cls.client_conn.send(config)

        print(f'Waiting for simulation result from the simulation-service daemon...')
        while cls.server_process.is_alive():
          if cls.client_conn.poll(10):
            sim_result = cls.client_conn.recv()
            return sim_result
      except Exception as e:
        print(f'Failed to run the scenario due to exception {e}. Retrying...')




 
    