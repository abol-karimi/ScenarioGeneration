#!/usr/bin/env python3
"""
Research question:
  Does prioritizing seeds based on their predicate-coverage improve the fuzzing performance?
"""


from random import Random

from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzzing.schedules.entropic import EntropicSchedule
from scenariogen.core.fuzzing.fuzzers.entropic import EntropicFuzzer
from scenariogen.core.coverages.coverage import PredicateCoverage, PredicateSetCoverage
from evaluation.configs import get_experiment_config, get_SUT_config, get_coverage_config


def get_config(ego, coverage, randomizer_seed, seeds_folder, max_total_time, output_folder):
    experiment_config = get_experiment_config(randomizer_seed, seeds_folder, max_total_time, output_folder)
    SUT_config = get_SUT_config(ego)
    coverage_config = get_coverage_config(coverage)

    config_randomizer = Random(randomizer_seed)
    config_seed_range = 1000
    mutator_seed = config_randomizer.randrange(config_seed_range)
    schedule_seed = config_randomizer.randrange(config_seed_range)

    generator_config = {
        'generator': EntropicFuzzer,
        'mutator-config': {
            'mutator': StructureAwareMutator(mutator_seed),
            'max-mutations-per-fuzz': experiment_config['max-mutations-per-fuzz'],
        },
        'schedule': EntropicSchedule(schedule_seed,
                                        0xFF,  # FeatureFrequencyThreshold
                                        100  # NumberOfRarestFeatures
                                    ),
        'feedback-types': (
            PredicateCoverage,
            PredicateSetCoverage,
            )
    }

    return {**experiment_config,
            'SUT-config': SUT_config,
            'coverage-config': coverage_config,
            **generator_config}
