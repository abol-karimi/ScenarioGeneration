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


def get_config(gen_ego, gen_coverage, randomizer_seed, max_total_time, output_folder):
  config_randomizer = Random(randomizer_seed)
  config_seed_range = 1000

  if gen_ego in {'TFPP', 'autopilot', None}:
    simulator = 'carla'
  elif gen_ego == 'intersectionAgent':
    simulator = 'newtonian'
  else:
    print(f'Are you sure you want to include agent {gen_ego} in the experiments?')
    exit(1)

  config = {
    'generator': AtherisFuzzer,
    'output-folder': output_folder,
    'results-file': f'{output_folder}/{gen_ego}_{gen_coverage}/results.json',
    'seeds-folder': f'experiments/seeds/random/seeds',
    'fuzz-inputs-folder': f"{output_folder}/fuzz-inputs",
    'events-folder': f"{output_folder}/{gen_ego}_{gen_coverage}/events",
    'bugs-folder': f"{output_folder}/{gen_ego}_{gen_coverage}/bugs",
    'SUT-config': {**SUT_config,
                  'ego-module': f'experiments.agents.{gen_ego}' if gen_ego else None,
                  'simulator': simulator,
                  },
    'coverage-config': {**coverage_config,
                        'coverage_module': gen_coverage
                        },
    'randomizer-seed': config_randomizer.randrange(config_seed_range),
    'max-seed-length': 1e+6, # 1 MB
    'max-total-time': max_total_time, # seconds
    'mutator-config':{'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                                       randomizer_seed=config_randomizer.randrange(config_seed_range)),
                      'max-mutations-per-fuzz': 10,
                      },
  }

  return config


if __name__ == '__main__':
  gen_ego = 'TFPP'
  gen_coverage = 'traffic-rules'
  randomizer_seed = 0
  max_total_time = 4*60*60
  output_folder = f'experiments/Atheris/{gen_ego}_{gen_coverage}_{randomizer_seed}_{max_total_time}'

  config = get_config(gen_ego, gen_coverage, randomizer_seed, max_total_time, output_folder)

  run(config)
