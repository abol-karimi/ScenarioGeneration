import time
import os
import jsonpickle
from pathlib import Path
import logging

from scenariogen.core.fuzzing.runner import SUTRunner


class SeedTester:
    def __init__(self, config):
        self.config = config
        self.seed_paths = sorted(Path(config['seeds-folder']).glob('*'), key=lambda x: os.path.getmtime(x))
        self.seed_index = 0

    def set_state(self, state):
        self.seed_index = state

    def get_state(self):
        return self.seed_index

    def input_eval(self, seed, SUT_config, coverage_config, save_events=True):
        sim_result = SUTRunner.run({**SUT_config,
                                    **coverage_config,
                                    **seed.config,
                                    'fuzz-input': seed,
                                    })
        if (not sim_result is None) and 'coverage' in sim_result.records:
            # For debugging purposes, save events
            if save_events:
                with open(Path(self.config['events-folder'])/f'{seed.hexdigest}.json', 'w') as f:
                    f.write(jsonpickle.encode(sim_result.records['events'], indent=1))

            return sim_result.records['coverage']
        else:
            return None

    def gen_input(self):
        seed_path = self.seed_paths[self.seed_index]
        with open(seed_path, 'r') as f:
            seed = jsonpickle.decode(f.read())
        self.seed_index += 1

        return seed
    
    def run(self):
        seed = self.gen_input()
        statement_coverage = self.input_eval(seed, self.config['SUT-config'], self.config['coverage-config'])
        if not statement_coverage is None: # if fuzz-input is valid
            with open(Path(self.config['fuzz-inputs-folder'])/f'{seed.hexdigest}.json', 'wb') as f:
                f.write(seed.bytes)
            with open(Path(self.config['coverages-folder'])/f'{seed.hexdigest}.json', 'w') as f:
                f.write(jsonpickle.encode(statement_coverage, indent=1))

    def runs(self, generator_state):
        start_time = time.time()

        logger = logging.getLogger(__name__)

        if generator_state: # resume
            logger.debug('Setting the state of the fuzzer...')
            self.set_state(generator_state)
      
        while time.time()-start_time < self.config['max-total-time'] and self.seed_index < len(self.seed_paths):
            self.run()
        
        logger.info('Finished the runs. Returning the state...')
        return self.get_state()
