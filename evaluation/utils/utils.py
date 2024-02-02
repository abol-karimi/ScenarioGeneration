from evaluation.configs import SUT_config, coverage_config
from scenariogen.core.fuzzing.fuzzers.seed_tester import SeedTester


def get_test_config(gen_config, test_ego, test_coverage, max_total_time):
  if test_ego in {'TFPP', 'autopilot'}:
    simulator = 'carla'
  elif test_ego in {'intersectionAgent'}:
    simulator = 'newtonian'
  else:
    raise ValueError(f'Are you sure you want to include agent {test_ego} in the experiments?')
  
  output_folder = f"{gen_config['output-folder']}/{test_ego}_{test_coverage}"

  config = {
    'generator': SeedTester,
    'output-folder': output_folder,
    'results-file': f'{output_folder}/results.json',
    'seeds-folder': gen_config['fuzz-inputs-folder'],
    'fuzz-inputs-folder': f'{output_folder}/fuzz-inputs',
    'events-folder': f'{output_folder}/events',
    'bugs-folder': f'{output_folder}/bugs',
    'SUT-config': {**SUT_config,
                  'ego-module': f'evaluation.agents.{test_ego}' if test_ego else None,
                  'simulator': simulator,
                  },
    'coverage-config': {**coverage_config,
                        'coverage-module': test_coverage,
                        },
    'max-total-time': max_total_time,
  }

  return config

