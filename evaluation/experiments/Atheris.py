#!/usr/bin/env python3

from random import Random

# This project
from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzzing.fuzzers.atheris import AtherisFuzzer
from evaluation.configs import get_experiment_config, get_SUT_config, get_coverage_config


def get_config(ego, coverage, randomizer_seed, seeds_folder, max_total_time, output_folder):
    experiment_config = get_experiment_config(randomizer_seed, seeds_folder, max_total_time, output_folder)
    SUT_config = get_SUT_config(ego)
    coverage_config = get_coverage_config(coverage)

    config_randomizer = Random(randomizer_seed)
    config_seed_range = 1000
    mutator_seed = config_randomizer.randrange(config_seed_range)

    generator_config = {
        'generator': AtherisFuzzer,
        'mutator-config':{'mutator': StructureAwareMutator(mutator_seed),
                            'max-mutations-per-fuzz': experiment_config['max-mutations-per-fuzz'],
                            },
        'atheris-output-folder': f'{output_folder}/atheris-output',
    }

    return {**experiment_config,
            'SUT-config': SUT_config,
            'coverage-config': coverage_config,
            **generator_config}
