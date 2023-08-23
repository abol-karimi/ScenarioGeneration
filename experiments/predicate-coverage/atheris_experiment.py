#!/usr/bin/env python3.8

# This project
from scenariogen.core.mutators import StructureAwareMutator
from scenariogen.core.crossovers import StructureAwareCrossOver
from scenariogen.core.fuzzers.atheris import AtherisFuzzer

SUT_config = {
  'timestep': 0.05,
  'render': False,
  'weather': 'CloudySunset',
  'arrival_distance': 4,
  'stop_speed_threshold': 0.5,
  'closedLoop': True,
  'ego_module': 'experiments.agents.followRouteAvoidCollisions',
  'replay_raw': False,
  'simulator': 'newtonian',
  'coverage_module': 'scenariogen.core.coverages.traffic_rules_predicate_name',
}

experiment_name = 'TrafficRulesPredicateName'
fuzzer_config = {
  'SUT_config': SUT_config,
  'experiment_name': experiment_name,
  'seeds_folder': f'experiments/seeds',
  'output_folder': f'experiments/predicate-coverage/{experiment_name}',
  'mutator': StructureAwareMutator(max_parameters_size=50,
                                   max_mutations_per_iteration=1,
                                   randomizer_seed=0),
  'crossOver': StructureAwareCrossOver(max_parameters_size=50,
                                       max_attempts=1,
                                       randomizer_seed=0),
  'atheris_runs': 60*60, # each run takes under 3 seconds
  'max_seed_length': 1e+6, # 1 MB
}

atheris_fuzzer = AtherisFuzzer(fuzzer_config)
atheris_fuzzer.run()
atheris_fuzzer.save_state()




