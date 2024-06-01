"""
Generates random seeds using simulation.
1. A random route through the intersection is chosen for the VUT.
2. A random number of non-egos with random routes through the intersection are chosen.
3. All the vehicles (VUT and non-egos) are driven using the VUT's algorithm.
"""

from pathlib import Path
import jsonpickle
from random import Random
import logging
from collections import Counter

# This project
from scenariogen.core.fuzzing.runner import SUTRunner
from .base import Fuzzer


class FuzzCandidate:
    """Represent an input with additional attributes"""

    def __init__(self, fuzz_input):
        self.fuzz_input = fuzz_input
        
        #--- These will be needed for power schedules
        # For each feature, the number of times it was covered
        self.feature_frequency = Counter()     
        self.NumExecutedMutations = 0


class MutationFuzzer(Fuzzer):
    def __init__(self, config):
        super().__init__(config)
        self.feature_frequency = Counter()
        self.random = Random(config['randomizer-seed'])
        self.mutator = config['mutator-config']['mutator']
        self.schedule = config['schedule']
        
        self.seeds = []
        for seed_path in Path(config['seeds-folder']).glob('*'):
            with open(seed_path, 'r') as f:
                seed = jsonpickle.decode(f.read())
            self.seeds.append(seed)
        
        self.fuzz_candidates = []
        self.seed_index = 0
    
    def get_state(self):
        state = {
            'feature-frequency': self.feature_frequency,
            'random-state': self.random.getstate(),
            'mutator-state': self.mutator.get_state(),
            'schedule-state': self.schedule.get_state(),
            'fuzz-candidates': self.fuzz_candidates,
            'seed-index': self.seed_index,
        }
        return state

    def set_state(self, state):
        self.feature_frequency = state['feature-frequency']
        self.random.setstate(state['random-state'])
        self.mutator.set_state(state['mutator-state'])
        self.schedule.set_state(state['schedule-state'])
        self.fuzz_candidates = state['fuzz-candidates']
        self.seed_index = state['seed-index']

    def input_eval(self, fuzz_input, SUT_config, coverage_config, save_events=True):
        logger = logging.getLogger(__name__)
        logger.info(f'Running SUT for fuzz input with hash {fuzz_input.hexdigest}')
        sim_result = SUTRunner.run({**SUT_config,
                                    **coverage_config,
                                    **fuzz_input.config,
                                    'fuzz-input': fuzz_input,
                                    })
        if sim_result is None:
            logger.info(f'Fuzz input with hash {fuzz_input.hexdigest} is invalid.')
            return None
        elif not 'coverage' in sim_result.records:
            logger.info(f'Fuzz input with hash {fuzz_input.hexdigest} did not record coverage.')
            return None
        else:
            logger.info(f'Fuzz input with hash {fuzz_input.hexdigest} recorded coverage.')
            # For debugging purposes, save events
            if save_events:
                with open(Path(self.config['events-folder'])/f'{fuzz_input.hexdigest}.json', 'w') as f:
                    f.write(jsonpickle.encode(sim_result.records['events'], indent=1))

            return sim_result.records['coverage']


    def fuzz(self):
        """Generates a new input by fuzzing a candidate in the population"""
        selected = self.schedule.choose(self.fuzz_candidates)
        selected.NumExecutedMutations += 1

        # Stacking: Apply multiple mutations to generate the candidate
        fuzz_input = selected.fuzz_input
        mutations_per_fuzz = self.random.randint(1, self.config['mutator-config']['max-mutations-per-fuzz'])
        for i in range(mutations_per_fuzz):
                fuzz_input = self.mutator.mutate(fuzz_input)
        return fuzz_input
  
    def gen_input(self):
        """First returns each seed once, then generates new inputs"""
        if self.seed_index < len(self.seeds):
            # Still seeding
            fuzz_input = self.seeds[self.seed_index]
            self.seed_index += 1
        else:
            # Fuzzing
            fuzz_input = self.fuzz()

        return fuzz_input

    def run(self):
        logger = logging.getLogger(__name__)

        new_fuzz_candidate = None
        fuzz_input = self.gen_input()
        statement_coverage = self.input_eval(fuzz_input, self.config['SUT-config'], self.config['coverage-config'])
        if not statement_coverage is None: # if fuzz-input is valid
            logger.info(f'The fuzz input with hash {fuzz_input.hexdigest} is valid. Will save it and its coverage.')
            with open(Path(self.config['fuzz-inputs-folder'])/f'{fuzz_input.hexdigest}.json', 'wb') as f:
                f.write(fuzz_input.bytes)
            with open(Path(self.config['coverages-folder'])/f'{fuzz_input.hexdigest}.json', 'w') as f:
                f.write(jsonpickle.encode(statement_coverage, indent=1))

            features = {item
                        for feedback_type in self.config['feedback-types']
                        for item in statement_coverage.cast_to(feedback_type).items
                        }
            if all(self.feature_frequency[f] > 0 for f in features):
                # No new features were discovered, so the fuzz input is not added to the fuzz candidates.
                # Update the global coverage frequencies
                self.schedule.update_coverage_frequency(self.fuzz_candidates, features)
            else:
                # Add the fuzz_input to the candidates
                new_fuzz_candidate = self.instantiate_fuzz_candidate(fuzz_input, features)
                self.fuzz_candidates.append(new_fuzz_candidate)
                logger.info(f'The fuzz input with hash {fuzz_input.hexdigest} expanded the coverage! Added to fuzz candidates.')
                
                # Reset the global coverage frequencies
                self.schedule.reset_coverage_frequency()

        return new_fuzz_candidate, statement_coverage

    def instantiate_fuzz_candidate(self, fuzz_input, features):
        fuzz_candidate = FuzzCandidate(fuzz_input)
        fuzz_candidate.feature_frequency.update(features)
        return fuzz_candidate