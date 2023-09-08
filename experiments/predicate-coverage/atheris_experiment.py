#!/usr/bin/env python3.8

# This project
from scenariogen.core.mutators import StructureAwareMutator
from scenariogen.core.crossovers import StructureAwareCrossOver
from scenariogen.core.fuzzers.atheris import AtherisFuzzer
from scenariogen.core.coverages.predicate_coverage import from_corpus

SUT_config = {
  'timestep': 0.05,
  'render': False,
  'weather': 'CloudySunset',
  'arrival_distance': 4,
  'stop_speed_threshold': 0.5,
  'closedLoop': False,
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
  'mutator': StructureAwareMutator(max_spline_knots_size=50,
                                   max_mutations_per_iteration=1,
                                   randomizer_seed=0),
  'crossOver': StructureAwareCrossOver(max_spline_knots_size=50,
                                       max_attempts=1,
                                       randomizer_seed=0),
  'atheris_runs': 2, # each run takes under 3 seconds
  'max_seed_length': 1e+6, # 1 MB
}

atheris_fuzzer = AtherisFuzzer(fuzzer_config)
atheris_fuzzer.run()
atheris_fuzzer.save_state()

# Coverage results
# predicate_coverage_corpus = f'experiments/predicate-coverage/{experiment_name}/predicate-coverage'
# coverage_space, coverage = from_corpus(SUT_config, predicate_coverage_corpus)
# print('Coverage ratio:', 1 if len(coverage_space) == 0 else len(coverage)/len(coverage_space))
# print('Coverage gap:', coverage_space-coverage)



