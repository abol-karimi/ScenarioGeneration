import logging

from scenariogen.core.fuzzing.fuzzers.counting import CountingPredicateSetFuzzer


class PreCheckFuzzer(CountingPredicateSetFuzzer):

    def gen_input(self):
        logger = logging.getLogger(__name__)

        statement_coverage = None
        while statement_coverage is None:
            fuzz_input = super().gen_input()
            logger.debug(f'Precheck validity of fuzz input with hash {fuzz_input.hexdigest}')
            statement_coverage = self.input_eval(fuzz_input,
                                                 self.config['precheck-SUT-config'],
                                                 self.config['precheck-coverage-config'],
                                                 save_events=False)
        logger.debug(f'Fuzz input with hash {fuzz_input.hexdigest} passed the precheck!')
        return fuzz_input
