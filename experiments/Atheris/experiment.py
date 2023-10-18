#!/usr/bin/env python3.8

# This project
from scenariogen.core.mutators import StructureAwareMutator
from scenariogen.core.crossovers import StructureAwareCrossOver
from scenariogen.core.fuzzers.atheris import AtherisFuzzer

SUT_config = {
  'render_spectator': False,
  'render_ego': False,
  'weather': 'CloudySunset',
  'arrival_distance': 4,
  'stopping_speed': 0.5,
  'moving_speed': 0.6,
  'closedLoop': True,
  'ego_module': 'experiments.agents.autopilot_route',
  'simulator': 'carla',
  'coverage_module': 'scenariogen.core.coverages.traffic_rules_predicates',
}

fuzzer_config = {
  'SUT_config': SUT_config,
  'seeds_folder': f'experiments/seeds_random',
  'output_folder': f'experiments/Atheris/output',
  'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                   max_mutations_per_iteration=1,
                                   randomizer_seed=0),
  'crossOver': StructureAwareCrossOver(max_spline_knots_size=50,
                                       max_attempts=1,
                                       randomizer_seed=0),
  'atheris_runs': 20,
  'max_seed_length': 1e+6, # 1 MB
}

atheris_fuzzer = AtherisFuzzer(fuzzer_config)
atheris_fuzzer.run()
atheris_fuzzer.save_state()




