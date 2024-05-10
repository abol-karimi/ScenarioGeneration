#!/usr/bin/env python3

from scenariogen.core.fuzzing.fuzzers.seed_tester import SeedTester
from evaluation.configs import get_experiment_config


def get_config(ego, coverage, seeds_folder, max_total_time, output_folder):
  config = get_experiment_config(ego, coverage, None, seeds_folder, max_total_time, output_folder)
  
  fuzzer_config = {
    'generator': SeedTester,
  }

  return {**config, **fuzzer_config}
