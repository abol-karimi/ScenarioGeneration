#!/usr/bin/env python3.8
import scenariogen.core.coverages.predicate_coverage as predicate_coverage

predicate_coverage_corpus = f'experiments/seeds_random'
config = {
  'ego_module': 'experiments.agents.autopilot_dest',
  'coverage_module': 'scenariogen.core.coverages.traffic_rules_predicate_names',
  'arrival_distance': 4,
}
coverage = predicate_coverage.from_corpus(predicate_coverage_corpus, config)
