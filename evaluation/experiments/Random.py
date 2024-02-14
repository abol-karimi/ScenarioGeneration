#!/usr/bin/env python3.8
"""
Research question:
  Can we beat random search as a baseline?
"""


from random import Random

from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzzing.schedules import RandomSchedule
from scenariogen.core.fuzzing.fuzzers.mutation import MutationFuzzer
from evaluation.configs import get_experiment_config


def get_config(gen_ego, gen_coverage, randomizer_seed, seeds_folder, max_total_time, output_folder):
  config = get_experiment_config(gen_ego, gen_coverage, randomizer_seed, seeds_folder, max_total_time, output_folder)
  
  config_randomizer = Random(randomizer_seed)
  config_seed_range = 1000
  mutator_seed = config_randomizer.randrange(config_seed_range)
  schedule_seed = config_randomizer.randrange(config_seed_range)

  fuzzer_config = {
    'generator': MutationFuzzer,
    'mutator-config': {
      'mutator': StructureAwareMutator(mutator_seed),
      'max-mutations-per-fuzz': config['max-mutations-per-fuzz'],
     },
    'schedule': RandomSchedule(schedule_seed),
  }

  return {**config, **fuzzer_config}
