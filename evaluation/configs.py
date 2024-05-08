from scenariogen.core.coverages.coverage import Predicate, StatementCoverage


SUT_config = {
  'render-spectator': False,
  'render-ego': False,
  'weather': 'CloudySunset',
  'simulator': None,
  'ego-module': None,
}


coverage_config = {
  'min_perceptible_time': 0.5,
  'arrival_distance': 4,
  'stopping_speed': 0.5,
  'moving_speed': 0.6,
  'coverage-module': None,
}


def ego_violations_coverage_filter(cov):
  statements = (s for s in cov.items if
    (s.predicate in {Predicate('violatesRule'),
                     Predicate('violatesRightOfForRule'),
                     Predicate('collidedWithAtTime')} \
      and s.args[0] == 'ego'
    ) \
    or s.predicate in {Predicate('egoNonegoCollision'),
                       Predicate('egoPropCollision')}
  )
  return StatementCoverage(statements)


def get_experiment_config(gen_ego, gen_coverage, randomizer_seed, seeds_folder, max_total_time, output_folder):

  if gen_ego in {'TFPP', 'autopilot', 'BehaviorAgent', 'BehaviorAgentRSS', None}:
    simulator = 'carla'
  elif gen_ego == 'intersectionAgent':
    simulator = 'newtonian'
  else:
    raise ValueError(f'Are you sure you want to include agent {gen_ego} in the experiments?')

  config = {
    'output-folder': output_folder,
    'results-file': f'{output_folder}/{gen_ego}_{gen_coverage}/results.json',
    'seeds-folder': seeds_folder,
    'fuzz-inputs-folder': f"{output_folder}/fuzz-inputs",
    'events-folder': f"{output_folder}/{gen_ego}_{gen_coverage}/events",
    'coverages-folder': f"{output_folder}/{gen_ego}_{gen_coverage}/coverages",
    'bugs-folder': f"{output_folder}/{gen_ego}_{gen_coverage}/bugs",
    'SUT-config': {**SUT_config,
                  'ego-module': f'evaluation.agents.{gen_ego}' if gen_ego else None,
                  'simulator': simulator,
                  },
    'coverage-config': {**coverage_config,
                        'coverage-module': gen_coverage
                        },
    'randomizer-seed': randomizer_seed,
    'max-seed-length': 1e+6, # 1 MB
    'max-mutations-per-fuzz': 10,
    'max-total-time': max_total_time, # seconds
  }

  return config