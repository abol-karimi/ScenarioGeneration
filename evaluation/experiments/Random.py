#!/usr/bin/env python3

from random import Random

# This project
from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzzing.schedules import RandomSchedule
from scenariogen.core.fuzzing.fuzzers.mutation import MutationFuzzer
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
        'generator': MutationFuzzer,
        'mutator-config': {
            'mutator': StructureAwareMutator(mutator_seed),
            'max-mutations-per-fuzz': experiment_config['max-mutations-per-fuzz'],
        },
        'schedule': RandomSchedule(schedule_seed),
    }

    return {**experiment_config,
            'SUT-config': SUT_config,
            'coverage-config': coverage_config,
            **generator_config}
