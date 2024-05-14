import sys
import multiprocessing
import threading
import subprocess
import time
import setproctitle
import signal
import ctypes
from queue import Queue, Empty
from dataclasses import dataclass
from typing import Any
import logging

import scenic
scenic.setDebuggingOptions(verbosity=0, fullBacktrace=True)
from scenic.simulators.carla.simulator import CarlaSimulator
from scenic.core.simulators import SimulationCreationError
from scenic.core.dynamics import GuardViolation

from srunner.scenariomanager.carla_data_provider import CarlaDataProvider

from scenariogen.core.utils import ordinal, get_free_port
from scenariogen.core.logging.client import configure_logger, TextIOBaseToLog
import scenariogen.core.logging.server as log_server

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


def log_carla_output(carla_process):
    logger = logging.getLogger(f'{__name__}.sim-service.carla')
    logger.info('Started logging Carla output...')

    while True:
        line = carla_process.stdout.readline()
        if not line:
            logger.info('Stopped logging Carla output.')
            break
        logger.info(line)


def fulfill_request(config, carla_server_process, simulator, connection):
    logger = logging.getLogger(f'{__name__}.sim-service.response')
    sim_result = None
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
            logger.exception(f'AssertionError when creating the initial scene:', exc_info=True)
            logger.info('Stopping the simulation service...')
            logging.shutdown()
            exit(1)
        except Exception:
            logger.exception(f'Failed to create the initial scene:', exc_info=True)
            break

        try:
            if (not carla_server_process is None) and not carla_server_process.poll() is None:
                logger.warning(f'Carla server exited with return code {carla_server_process.returncode}')
                carla_server_process = None

            if carla_server_process is None:
                CarlaDataProvider.set_rpc_port(get_free_port())
                CarlaDataProvider.set_streaming_port(get_free_port())
                CarlaDataProvider.set_secondary_port(get_free_port())
                CarlaDataProvider.set_traffic_manager_port(get_free_port())
                logger.info('Starting the Carla server...')
                carlaUE4_options = ["CarlaUE4",
                                    "-nosound",
                                    f"-carla-rpc-port={CarlaDataProvider.get_rpc_port()}",
                                    f"-carla-streaming-port={CarlaDataProvider.get_streaming_port()}",
                                    f"-carla-secondary-port={CarlaDataProvider.get_secondary_port()}",
                                    ]
                carlaUE4_options.append('' if config['render-spectator'] or config['render-ego'] else '-RenderOffScreen')
                carla_server_process = subprocess.Popen(["/home/scenariogen/carla/CarlaUE4/Binaries/Linux/CarlaUE4-Linux-Shipping"]+carlaUE4_options,
                                                        preexec_fn=set_pdeathsig(signal.SIGKILL),
                                                        text=True,
                                                        stdout=subprocess.PIPE,
                                                        stderr=subprocess.STDOUT
                                                    )
                logger.info('Waiting 10 seconds for Carla process to start...')
                time.sleep(10)
                logger.info('Assuming Carla process started...')

                log_thread = threading.Thread(target=log_carla_output,
                                            args=(carla_server_process,),
                                            daemon=True)
                log_thread.start()

                logger.info('Waiting 10 seconds for Carla to load map...')
                time.sleep(10)
                logger.info('Assuming Carla finished loading the map...')

                if not carla_server_process.poll() is None:
                    logger.error(f'Carla crashed immediately with exit code {carla_server_process.returncode}!')

            if simulator is None:
                logger.info('Connecting to the Carla simulator...')
                simulator = CarlaSimulator(carla_map=config['carla-map'],
                                            map_path=config['map'],
                                            timestep=config['timestep'],
                                            render=config['render-ego'],
                                            timeout=30,
                                            port=CarlaDataProvider.get_rpc_port(),
                                            traffic_manager_port=CarlaDataProvider.get_traffic_manager_port())
                
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
            logger.exception(f'Failed to simulate the scenario:', exc_info=True)
            break
        except Exception as e:
            run_callbacks(cleanup_callbacks)
            simulator.world.tick()
            logger.exception(f'Failed to simulate the scenario:', exc_info=True)
            logger.info('Will try again...')
        else:
            run_callbacks(cleanup_callbacks)
            simulator.world.tick()
            if simulation:
                sim_result = SimResult.from_simulation(simulation)
            else:
                logger.debug('CarlaSimulator.simulate() returned None.')

            break
    
    connection.send(sim_result)
    return carla_server_process, simulator


def simulation_service(connection, log_queue, sync_lock):
    """Reads scenario config from connection, then writes sim_result to connection.
    Runs as a separate process to isolate the main process from crashes in Scenic, VUT, or Carla.
    """
    sync_lock.release()

    setproctitle.setproctitle('sim-service')

    configure_logger(log_queue)
    logger = logging.getLogger(f'{__name__}.sim-service')
    # capture stdout and stderr to the logs as well
    sys.stdout = TextIOBaseToLog(logger.debug)
    sys.stderr = TextIOBaseToLog(logger.warning)

    carla_server_process = None
    simulator = None

    # service loop
    while True:
        try:
            config = connection.recv()
        except EOFError:
            logger.warning(f'Client closed the connection. Ending the simulation service...')
            connection.close()
            break
        else:
            logger.info('Simulation service received a request.')

        # For any received simulation config, we must send a simulation result (even if the result is None).
        # In case of a simulator crash (e.g. Carla segmentation fault), the service restarts the simulator and tries again.
        # In case of a service crash, the client is informed by calling is_alive. Then the client restarts the service and resends the request.
        carla_server_process, simulator = fulfill_request(config, carla_server_process, simulator, connection)



class SUTRunner:
    ctx = multiprocessing.get_context('spawn')
    server_process = None
    crashes = 0
 
    @classmethod
    def start_simulation_service(cls):
        logger = logging.getLogger(__name__)
        logger.info(f"Starting the simulation service...")
        sync_lock = cls.ctx.Lock()
        cls.client_conn, cls.server_conn = cls.ctx.Pipe(duplex=True)
        cls.server_process = cls.ctx.Process(target=simulation_service,
                                            args=(cls.server_conn, log_server.queue, sync_lock),
                                            name='sim-service',
                                            daemon=True)
        sync_lock.acquire()
        cls.server_process.start()
        sync_lock.acquire()
        # By now, the cls.server_process has started and we may call its is_alive()
        sync_lock.release()

    @classmethod
    def run(cls, config):
        """ Runs the scenario.
        Keeps retrying if the simulation server process exits with an error.
        """
        # The first time this method is called, server_process is run for the first time
        if cls.server_process is None:
            cls.start_simulation_service()

        logger = logging.getLogger(__name__)
        while True:
            try:
                if not cls.server_process.is_alive():
                    cls.crashes += 1
                    logger.warning(f"Simulation service crashed for the {ordinal(cls.crashes)} time! Restarting the service...")
                    cls.server_process.close()
                    cls.client_conn.close()
                    cls.server_conn.close()
                    cls.start_simulation_service()
                else:
                    logger.info('Sending a request to the simulation service...')
                    cls.client_conn.send(config)

                    logger.info(f'Waiting for simulation result from the simulation service...')
                    while cls.server_process.is_alive():
                        if cls.client_conn.poll(10):
                            sim_result = cls.client_conn.recv()
                            if sim_result:
                                logger.info(f'Simulation completed successfully.')
                            else:
                                logger.info(f"Simulation rejected fuzz-input with hash {config['fuzz-input'].hexdigest}")
                            return sim_result
            except Exception:
                logger.exception(f'Failed to run the scenario:', exc_info=True)
                logger.info('Retrying...')




 
    