import logging
import jsonpickle
from pathlib import Path
import time
from random import Random

from .fuzzer_corpus import InputCorpus
from scenariogen.core.fuzzing.runner import SUTRunner


class EntropicFuzzer:
    def __init__(self, config):
        self.config = config
        self.random = Random(config['randomizer-seed'])
        self.mutator = config['mutator-config']['mutator']

        self.fuzz_candidates = []

        self.Corpus = InputCorpus(config['schedule-seed'],
                                  config['FeatureFrequencyThreshold'],
                                  config['NumberOfRarestFeatures'])
        self.start_time = None

    def RunOne(self, fuzz_input, II, OutFoundUniqueFeatures):
        logger = logging.getLogger(__name__)
        statement_coverage = self.input_eval(fuzz_input,
                                             self.config['SUT-config'],
                                             self.config['coverage-config'])
        if statement_coverage is None:
            # if the input was rejected by the SUT
            return False
        
        logger.info(f'The fuzz input with hash {fuzz_input.hexdigest} is valid. Will save it and its coverage.')
        with open(Path(self.config['fuzz-inputs-folder'])/f'{fuzz_input.hexdigest}.json', 'wb') as f:
            f.write(fuzz_input.bytes)
        with open(Path(self.config['coverages-folder'])/f'{fuzz_input.hexdigest}.json', 'w') as f:
            f.write(jsonpickle.encode(statement_coverage, indent=1))

        UniqFeatureSetTmp = set()
        FoundUniqFeaturesOfII = 0
        NumUpdatesBefore = self.Corpus.NumFeatureUpdates()

        for feedback_type in self.config['feedback-types']:
            for feature in statement_coverage.cast_to(feedback_type).items:
                if self.Corpus.AddFeature(feature):
                    UniqFeatureSetTmp.add(feature)
                self.Corpus.UpdateFeatureFrequency(II, feature)
                if II is not None:
                    FoundUniqFeaturesOfII += 1
        
        if OutFoundUniqueFeatures is not None:
            OutFoundUniqueFeatures = FoundUniqFeaturesOfII
        
        NumNewFeatures = self.Corpus.NumFeatureUpdates() - NumUpdatesBefore
        if NumNewFeatures > 0:
            self.Corpus.AddToCorpus(fuzz_input,
                                    NumNewFeatures,
                                    UniqFeatureSetTmp)
            return True

        return False

    def MutateAndTestOne(self):
        II = self.Corpus.ChooseUnitToMutate()

        mutant = self.Mutate(II.U)

        II.NumExecutedMutations += 1
        self.Corpus.IncrementNumExecutedMutations()

        FoundUniqFeatures = False
        self.RunOne(mutant, II, FoundUniqFeatures)
        II.NeedsEnergyUpdate = True

    def Mutate(self, fuzz_input):
        mutations_per_fuzz = self.random.randint(1, self.config['mutator-config']['max-mutations-per-fuzz'])
        # Stacking: Apply multiple mutations to generate the mutant
        for i in range(mutations_per_fuzz):
            fuzz_input = self.mutator.mutate(fuzz_input)
        return fuzz_input

    def ReadAndExecuteSeedCorpora(self):
        # Load and execute inputs one by one.
        for seed_path in Path(self.config['seeds-folder']).glob('*'):
            with open(seed_path, 'r') as f:
                U = jsonpickle.decode(f.read())
            
            self.RunOne(U,
                        None, # II
                        None, # OutFoundUniqueFeatures
                        )
            if self.TimedOut():
                break
    
    def runs(self, fuzzer_state=None):
        self.start_time = time.time()

        logger = logging.getLogger(__name__)
        logger.debug(f"Running {type(self).__name__} for {self.config['max-total-time']} seconds...")

        if fuzzer_state:
            logger.debug('Resume is not implemented for EntropicFuzzer.')
            return None

        self.ReadAndExecuteSeedCorpora()

        while not self.TimedOut():
            self.MutateAndTestOne()

        logger.info('Finished the runs.')
        return None

    def TimedOut(self):
        return time.time()-self.start_time >= self.config['max-total-time']

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