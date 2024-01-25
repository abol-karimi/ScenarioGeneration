#!/usr/bin/env python3.8
"""
Research question:
  Does prioritizing seeds based on their predicate-coverage improve the fuzzing performance?
"""


from random import Random

from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzzing.schedules import AFLFastSchedule
from scenariogen.core.fuzzing.fuzzers.modular import CountingPredicateSetFuzzer
from experiments.configs import SUT_config, coverage_config
from experiments.runner import run


gen_ego = 'TFPP'
gen_coverage = 'traffic-rules'
config_randomizer_seed = 0
config_randomizer = Random(config_randomizer_seed)
config_seed_range = 1000

config = {
  'generator': CountingPredicateSetFuzzer,
  'results-file': f'experiments/PCGF/gen_{gen_ego}_{gen_coverage}/results.json',
  'SUT-config': {**SUT_config,
                'ego-module': f'experiments.agents.{gen_ego}' if gen_ego else None,
                'simulator': 'carla',
                },
  'coverage-config': {**coverage_config,
                      'coverage_module': gen_coverage
                      },
  'seeds-folder': f'experiments/seeds/random/seeds',
  'fuzz-inputs-folder': f"experiments/PCGF/gen_{gen_ego}_{gen_coverage}/fuzz-inputs",
  'events-folder': f"experiments/PCGF/gen_{gen_ego}_{gen_coverage}/test_{gen_ego}_{gen_coverage}/events",
  'bugs-folder': f"experiments/PCGF/gen_{gen_ego}_{gen_coverage}/test_{gen_ego}_{gen_coverage}/bugs",
  'randomizer-seed': config_randomizer.randrange(config_seed_range),
  'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                  randomizer_seed=config_randomizer.randrange(config_seed_range)),
  'max-mutations-per-fuzz': 10,
  'schedule': AFLFastSchedule(config_randomizer.randrange(config_seed_range), 5),
  'max-seed-length': 1e+6, # 1 MB
  'max-total-time': 4*60*60, # seconds
}

if __name__ == '__main__':
  run(config)


