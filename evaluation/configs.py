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


def ego_collisions_coverage_filter(cov):
    statements = (s for s in cov.items if
        (s.predicate.name == 'collidedWithAtTime' \
        and s.args[0] == 'ego'
        )
    )
    return StatementCoverage(statements)


def get_experiment_config(randomizer_seed, seeds_folder, max_total_time, output_folder):

    config = {
        'output-folder': output_folder,
        'results-file': f'{output_folder}/results.json',
        'seeds-folder': seeds_folder,
        'fuzz-inputs-folder': f'{output_folder}/fuzz-inputs',
        'events-folder': f'{output_folder}/events',
        'coverages-folder': f'{output_folder}/coverages',
        'bugs-folder': f'{output_folder}/bugs',
        'logs-folder': f'{output_folder}/logs',
        'randomizer-seed': randomizer_seed,
        'max-seed-length': 1e+6, # 1 MB
        'max-mutations-per-fuzz': 10,
        'measurement-period': 60, # seconds
        'max-total-time': max_total_time, # seconds
        'kill-timeout': max_total_time + 15*60,
    }

    return config


def get_SUT_config(ego):
    if ego in {'TFPP', 'autopilot', 'BehaviorAgent', 'BehaviorAgentRSS'}:
        simulator = 'carla'
    elif ego is None or ego in {'intersectionAgent'}:
        simulator = 'newtonian'
    else:
        raise ValueError(f'Are you sure you want to include agent {ego} in the experiments?')

    config = {
        **SUT_config,
        'ego-module': f'evaluation.agents.{ego}' if ego else None,
        'simulator': simulator,
    }

    return config


def get_coverage_config(coverage):
    config = {
        **coverage_config,
        'coverage-module': coverage,
    }
    
    return config
