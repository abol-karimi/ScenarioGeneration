import logging

import scenariogen.core.fuzzing.runners.carla as carla_runner
import scenariogen.core.fuzzing.runners.newtonian as newtonian_runner


class SUTRunner:
    """ Dispatches the simulation request to the appropriate runner. """
    @classmethod
    def run(cls, config):
        logger = logging.getLogger(__name__)
        if config['simulator'] == 'carla':
            logger.debug('Dispatching the simulation request to the CARLA runner...')
            return carla_runner.SUTRunner.run(config)
        elif config['simulator'] == 'newtonian':
            logger.debug('Dispatching the simulation request to the Newtonian runner...')
            return newtonian_runner.SUTRunner.run(config)
