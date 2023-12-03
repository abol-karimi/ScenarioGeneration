SUT_config = {
  'render_spectator': False,
  'render_ego': False,
  'weather': 'CloudySunset',
  'ego_module': None,
  'simulator': 'carla',
  'coverage_module': None,
}

coverage_config = {
  'arrival_distance': 4,
  'stopping_speed': 0.5,
  'moving_speed': 0.6,
  'coverage_module': 'scenariogen.core.coverages.traffic_rules_statements',
}