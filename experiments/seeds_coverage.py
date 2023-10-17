#!/usr/bin/env python3.8
from scenariogen.core.coverages.coverage import from_corpus

SUT_inputs_corpus = f'experiments/seeds_random'
config = {
  'ego_module': 'experiments.agents.autopilot_dest',
  'coverage_module': 'scenariogen.core.coverages.traffic_rules_predicates',
  'arrival_distance': 4,
  'stopping_speed': 0.5,
  'moving_speed': 0.6,
}
coverage = from_corpus(SUT_inputs_corpus, config)
coverage.print()
