#!/usr/bin/env python3

# This project
from scenariogen.core.seed_generators.scenic import RandomSeedGenerator
from evaluation.configs import get_experiment_config, get_SUT_config, get_coverage_config


def get_config(ego, coverage, randomizer_seed, seeds_folder, max_total_time, output_folder):
    experiment_config = get_experiment_config(randomizer_seed, seeds_folder, max_total_time, output_folder)
    SUT_config = get_SUT_config(ego)
    coverage_config = get_coverage_config(coverage)

    generator_config = {
        'generator': RandomSeedGenerator, # TODO refactor RandomSeedGenerator to accept the new config format
        'scenario-file': f'evaluation/seeds/random/definitions/4way-stop.scenic',
        'save-coverage-events': True,
        'spline-degree': 3,
        'scene-maxIterations': 50,
        'simulate-maxIterations': 1,
        }

    return {**experiment_config,
            'SUT-config': SUT_config,
            'coverage-config': coverage_config,
            **generator_config}

