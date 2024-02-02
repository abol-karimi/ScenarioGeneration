#!/usr/bin/env python3.8
"""
Research question:
  Does prioritizing seeds based on their predicate-coverage improve the fuzzing performance?
"""


from random import Random

from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzzing.schedules import AFLFastSchedule
from scenariogen.core.fuzzing.fuzzers.modular import CountingPredicateSetFuzzer
from evaluation.configs import get_experiment_config


def get_config(gen_ego, gen_coverage, randomizer_seed, seeds_folder, max_total_time, output_folder):
  config = get_experiment_config(gen_ego, gen_coverage, randomizer_seed, seeds_folder, max_total_time, output_folder)
  
  config_randomizer = Random(randomizer_seed)
  config_seed_range = 1000
  mutator_seed = config_randomizer.randrange(config_seed_range)
  schedule_seed = config_randomizer.randrange(config_seed_range)

  PCGF_config = {
    'generator': CountingPredicateSetFuzzer,
    'mutator-config': {
      'mutator': StructureAwareMutator(mutator_seed),
      'max-mutations-per-fuzz': config['max-mutations-per-fuzz'],
     },
    'schedule': AFLFastSchedule(schedule_seed, 5),
  }

  return {**config, **PCGF_config}
