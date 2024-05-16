import time
import logging

class Fuzzer:
    def __init__(self, config):
        self.config = config

    def get_state(self):
        pass

    def set_state(self):
        pass

    def gen_input(self):
        pass

    def run(self):
        fuzz_input = self.gen_input()

    def runs(self, fuzzer_state=None):
        start_time = time.time()

        logger = logging.getLogger(__name__)

        if fuzzer_state:
            logger.debug('Setting the state of the fuzzer...')
            self.set_state(fuzzer_state)

        logger.debug(f"Running {type(self).__name__} for {self.config['max-total-time']} seconds...")
        while time.time()-start_time < self.config['max-total-time']:
            self.run()

        logger.info('Finished the runs. Returning the state...')
        return self.get_state()
