import scenariogen.core.fuzzing.runners.carla as carla_runner

class SUTRunner:
    """ Dispatches the simulation request to the appropriate runner. """
    @classmethod
    def run(cls, config):
        if config['simulator'] == 'carla':
            return carla_runner.SUTRunner.run(config)
