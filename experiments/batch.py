# Run several experiments, populate results, plot the graphs
import importlib

from experiments.configs import SUT_config, coverage_config

fuzzer_config = {
  'SUT-config': {**SUT_config,
                'simulator': 'carla',
                'ego-module': f'experiments.agents.TFPP',
                },
  'coverage-config': {**coverage_config,
                      'coverage_module': 'traffic'
                      },
  'seeds-folder': f'experiments/seeds/random/seeds',
  'fuzz-inputs-folder': f"experiments/Atheris/gen_{gen_ego}_{gen_coverage}/fuzz-inputs",
  'events-folder': f"experiments/Atheris/gen_{gen_ego}_{gen_coverage}/test_{gen_ego}_{gen_coverage}/events",
  'bugs-folder': f"experiments/Atheris/gen_{gen_ego}_{gen_coverage}/test_{gen_ego}_{gen_coverage}/bugs",
  'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                  randomizer_seed=config_randomizer.randrange(config_seed_range)),
  'max_total_time': max_total_time, # seconds
  'max-seed-length': 1e+6, # 1 MB
}

experiments_config = (
  # ('Atheris', 'random', 'TFPP', 'traffic', 'TFPP', 'traffic'),
  ('random_search', None, 'TFPP', 'traffic', 'TFPP', 'traffic'),
)


for experiment_type, seeds, gen_ego, gen_coverage, test_ego, test_coverage in experiments_config:
  print(f'Now running report: {experiment_type, seeds, gen_ego, gen_coverage, test_ego, test_coverage}')

  importlib.import_module(f'experiments.{}')
