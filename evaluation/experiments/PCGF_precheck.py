#!/usr/bin/env python3
"""
Research question:
  Does prioritizing seeds based on their predicate-coverage improve the fuzzing performance?
"""


from scenariogen.core.fuzzing.fuzzers.precheck import PreCheckFuzzer
from evaluation.configs import get_SUT_config, get_coverage_config
from .PCGF import get_config as PCGF_get_config


def get_config(precheck_ego, precheck_coverage, ego, coverage, randomizer_seed, seeds_folder, max_total_time, output_folder):
    PCGF_config = PCGF_get_config(ego, coverage, randomizer_seed, seeds_folder, max_total_time, output_folder)

    precheck_SUT_config = get_SUT_config(precheck_ego)
    precheck_coverage_config = get_coverage_config(precheck_coverage)

    return {**PCGF_config,
            'generator': PreCheckFuzzer,
            'precheck-SUT-config': precheck_SUT_config,
            'precheck-coverage-config': precheck_coverage_config,
            }
