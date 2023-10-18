#!/usr/bin/env python3.8
from scenariogen.core.coverages.coverage import from_corpus
from scenariogen.predicates.utils import predicates_of_logic_program

SUT_inputs_corpus = f'experiments/seeds_random'
config = {
  'ego_module': 'experiments.agents.autopilot_route',
  'coverage_module': 'scenariogen.core.coverages.traffic_rules_predicates',
  'arrival_distance': 4,
  'stopping_speed': 0.5,
  'moving_speed': 0.6,
}
coverage = from_corpus(SUT_inputs_corpus, config)
coverage.print()


traffic_rules_file = '4way-stopOnAll.lp'
with open(f"src/scenariogen/predicates/{traffic_rules_file}", 'r') as f:
  traffic_rules = f.read()

coverage_space = predicates_of_logic_program(traffic_rules)
print(f'\nCoverage gap:')
(coverage_space-coverage).print()


