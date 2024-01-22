#!/usr/bin/env python3.8
"""
Research question:
  Does prioritizing seeds based on their predicate-coverage improve the fuzzing performance?
"""


from random import Random

# This project
from scenariogen.core.fuzzing.mutators import StructureAwareMutator
from scenariogen.core.fuzzing.fuzzers.atheris import AtherisFuzzer
from experiments.configs import SUT_config, coverage_config
from experiments.runner import run


if __name__ == '__main__':

  gen_ego = 'TFPP'
  gen_coverage = 'traffic'
  config_randomizer_seed = 0
  config_randomizer = Random(config_randomizer_seed)
  config_seed_range = 1000

  ego_coverage = f"{gen_ego if gen_ego else 'openLoop'}_{gen_coverage}"
  config = {
    'generator': AtherisFuzzer,
    'results-file': f'experiments/Atheris/gen_{ego_coverage}/results.json',
    'seeds-folder': f'experiments/seeds/random/seeds',
    'fuzz-inputs-folder': f"experiments/Atheris/gen_{ego_coverage}/fuzz-inputs",
    'events-folder': f"experiments/Atheris/gen_{ego_coverage}/test_{ego_coverage}/events",
    'bugs-folder': f"experiments/Atheris/gen_{ego_coverage}/test_{ego_coverage}/bugs",
    'SUT-config': {**SUT_config,
                  'ego-module': f'experiments.agents.{gen_ego}' if gen_ego else None,
                  'simulator': 'carla',
                  },
    'coverage-config': {**coverage_config,
                        'coverage_module': gen_coverage
                        },
    'mutator-config':{'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                                       randomizer_seed=config_randomizer.randrange(config_seed_range)),
                      'max-mutations-per-fuzz': 10,
                      },
    'randomizer-seed': config_randomizer.randrange(config_seed_range),
    'max-seed-length': 1e+6, # 1 MB
    'max-total-time': 4*60*60, # seconds
  }

  run(config)
