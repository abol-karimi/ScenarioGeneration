import logging

import scenic
from scenic.domains.driving.roads import Network
from scenic.simulators.newtonian.simulator import NewtonianSimulator
from scenic.core.simulators import SimulationCreationError
from scenic.core.dynamics import GuardViolation

from .types import SimResult


class SUTRunner:
    simulator = None

    @classmethod
    def run(cls, config):
        logger = logging.getLogger(__name__)
        try:
            scenario = scenic.scenarioFromFile(f"src/scenariogen/simulators/newtonian/SUT.scenic",
                                                params= {'map': config['map'],
                                                        'config': config
                                                        },
                                                mode2D=True)
            scene, _ = scenario.generate(maxIterations=1)
        except AssertionError:
            logger.exception(f'AssertionError when creating the initial scene:', exc_info=True)
            logger.info('Stopping the simulation service...')
            logging.shutdown()
            exit(1001)
        except Exception:
            logger.exception(f'Failed to create the initial scene:', exc_info=True)
            return None
        else:
            logger.debug('Initial scence created.')
        

        try:
            if cls.simulator is None:
                logger.info('Instantiating a NewtonianSimulator...')
                cls.simulator = NewtonianSimulator(network=Network.fromFile(config['map']),
                                                    render=config['render-spectator'])
            
            simulation = cls.simulator.simulate(scene,
                                                maxSteps=config['steps'],
                                                maxIterations=1,
                                                raiseGuardViolations=True)
        except (SimulationCreationError, GuardViolation) as e:
            logger.exception(f'Failed to simulate the scenario:', exc_info=True)
            logger.info('Returning a None result...')
            return None
        except Exception as e:
            logger.exception(f'Failed to simulate the scenario:', exc_info=True)
            logger.info('Will try again...')
        else:
            if simulation:
                return SimResult.from_simulation(simulation)
            else:
                return None
