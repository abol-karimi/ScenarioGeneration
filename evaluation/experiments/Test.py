#!/usr/bin/env python3

# This project
from scenariogen.core.fuzzing.fuzzers.seed_tester import SeedTester
from evaluation.configs import get_experiment_config, get_SUT_config, get_coverage_config


def get_config(ego, coverage, seeds_folder, max_total_time, output_folder):
    experiment_config = get_experiment_config(None, seeds_folder, max_total_time, output_folder)
    SUT_config = get_SUT_config(ego)
    coverage_config = get_coverage_config(coverage)

    generator_config = {
        'generator': SeedTester,
    }

    return {**experiment_config,
            'SUT-config': SUT_config,
            'coverage-config': coverage_config,
            **generator_config}
