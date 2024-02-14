import multiprocessing
import traceback
import subprocess
import time
import setproctitle
import signal
import ctypes
import torch
from queue import Queue, Empty
from dataclasses import dataclass
from typing import Any

import scenic
scenic.setDebuggingOptions(verbosity=0, fullBacktrace=True)
from scenic.domains.driving.roads import Network
from scenic.simulators.carla.simulator import CarlaSimulator
from scenic.simulators.newtonian.simulator import NewtonianSimulator
from scenic.core.simulators import SimulationCreationError
from scenic.core.dynamics import GuardViolation

from srunner.scenariomanager.carla_data_provider import CarlaDataProvider

from scenariogen.core.utils import ordinal


@dataclass(frozen=True)
class SimResult:
  trajectory : Any = None
  finalState : Any = None
  terminationType : Any = None
  terminationReason : Any = None
  records : Any = None

  @classmethod
  def from_simulation(cls, simulation):
    result = simulation.result
    return cls(result.trajectory,
               result.finalState,
               result.terminationType,
               result.terminationReason,
               result.records)


libc = ctypes.CDLL("libc.so.6")
def set_pdeathsig(sig):
  def callable():
      return libc.prctl(1, sig)
  return callable


def run_callbacks(callbacks):
  while not callbacks.empty():
    try:
      callback = callbacks.get(True, 1)
      callback()
    except Empty:
      continue


def simulation_service(connection):
  """Reads scenario config from connection, then writes sim_result to connection.
  Runs as a separate process to isolate the main process from crashes in Scenic, VUT, or Carla.
  """
  print(f'Simulation service started!')
  setproctitle.setproctitle('Sim-service')
  carla_server_process = None
  simulator = None

  # service loop
  while True:
    try:
      config = connection.recv()
    except EOFError:
      traceback.print_exc()
      print(f'Client closed the connection. Ending the simulation service...')
      connection.close()
      break
    else:
      print('Simulation service received a request.')

    # For any received simulation config, we must send a simulation result (even if the result is None).
    # In case of a simulator crash (e.g. Carla segmentation fault), the service restarts the simulator and tries again.
    # In case of a service crash, the client is informed by calling is_alive. Then the client restarts the service and resends the request.
    while True:
      try:
        cleanup_callbacks = Queue()
        scenario = scenic.scenarioFromFile(f"src/scenariogen/simulators/{config['simulator']}/SUT.scenic",
                                          params= {'map': config['map'],
                                                   'weather': config['weather'],
                                                   'config': config,
                                                   'cleanup_callbacks': cleanup_callbacks},
                                          mode2D=True)
        scene, _ = scenario.generate(maxIterations=1)
      except AssertionError:
        traceback.print_exc()
        print(f'Failed to create the initial scene due to AssertionError. Stopping the simulation service...')
        exit(1)
      except Exception as e:
        traceback.print_exc()
        print(f'Failed to create the initial scene due to an unexpected exception of type {type(e)}: {e}. Returning a None result...')
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
            carla_server_process = subprocess.Popen(["/home/carla/CarlaUE4/Binaries/Linux/CarlaUE4-Linux-Shipping", "CarlaUE4", render_option],
                                                    preexec_fn=set_pdeathsig(signal.SIGKILL)
                                                   )
            time.sleep(5)

          if simulator is None:
            simulator = CarlaSimulator(carla_map=config['carla-map'],
                                       map_path=config['map'],
                                       timestep=config['timestep'],
                                       render=config['render-ego'])
            
            # For Leaderboard agents
            CarlaDataProvider.set_client(simulator.client)
            CarlaDataProvider.set_world(simulator.world)
            simulator.world.tick()

            if not config['render-spectator']:
              settings = simulator.world.get_settings()
              settings.no_rendering_mode = True
              simulator.world.apply_settings(settings)

        simulation = simulator.simulate(scene,
                                        maxSteps=config['steps'],
                                        maxIterations=1,
                                        raiseGuardViolations=True)
      except (SimulationCreationError, GuardViolation) as e:
        run_callbacks(cleanup_callbacks)
        simulator.world.tick()
        traceback.print_exc()        
        print(f'Failed to simulate the scenario due to exception {e}. Returning a None result...')
        connection.send(None)
        break
      except torch.cuda.OutOfMemoryError as e:
        print(f'Failed to simulate the scenario due to exception {e}. Will close Carla and the simulation service, then try again...')
        carla_server_process.terminate()
        torch.cuda.empty_cache()
        exit(1)
      except Exception as e:
        run_callbacks(cleanup_callbacks)
        simulator.world.tick()
        traceback.print_exc()
        print(f'Failed to simulate the scenario due to unexpected exception {e}. Will try again...')
      else:
        run_callbacks(cleanup_callbacks)
        simulator.world.tick()
        if simulation:
          connection.send(SimResult.from_simulation(simulation))
        else:
          connection.send(None)

        break # simulation request fulfilled


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
          print(f"Starting the simulation service...")
          cls.server_process = cls.ctx.Process(target=simulation_service,
                                               args=(cls.server_conn,),
                                               name='Simulation service',
                                               daemon=True)
          cls.server_process.start()
        elif not cls.server_process.is_alive():
          cls.crashes += 1
          print(f"Simulation service crashed for the {ordinal(cls.crashes)} time! Restarting the service...")
          cls.server_process.close()
          cls.client_conn.close()
          cls.server_conn.close()      
          cls.client_conn, cls.server_conn = cls.ctx.Pipe(duplex=True)
          cls.server_process = cls.ctx.Process(target=simulation_service,
                                               name='Simulation service',
                                               args=(cls.server_conn,),
                                               daemon=True)
          cls.server_process.start()
        
        print('Sending a request to the simulation service...')
        cls.client_conn.send(config)

        print(f'Waiting for simulation result from the simulation service...')
        while cls.server_process.is_alive():
          if cls.client_conn.poll(10):
            sim_result = cls.client_conn.recv()
            if not sim_result:
              print(f'Simulation rejected fuzz-input with hash ', config['fuzz-input'].hexdigest)
            return sim_result
      except Exception as e:
        print(f'Failed to run the scenario due to exception {e}. Retrying...')




 
    