#!/usr/bin/env python3.8
import argparse
from scenariogen.core.coverages.coverage import from_corpus
from scenariogen.predicates.utils import predicates_of_logic_program

parser = argparse.ArgumentParser(
    description='Compute the predicate coverage of a corpus of SUT inputs.')
parser.add_argument('SUT_inputs_path',
                    help='relative path of the corpus folder')
parser.add_argument('--ego_module',
                    default='experiments.agents.autopilot',
                    help='the scenic file containing the ego scenario')
parser.add_argument('--predicates_file',
                    default='4way-stopOnAll.lp',
                    help='the logic program whose predicates define the predicate-coverage space')
parser.add_argument('--arrival_distance', default=4, type=float)
parser.add_argument('--stopping_speed', default=0.5, type=float)
parser.add_argument('--moving_speed', default=0.6, type=float)
args = parser.parse_args()

config = {
  'ego_module': args.ego_module,
  'coverage_module': 'scenariogen.core.coverages.traffic_rules_predicates',
  'arrival_distance': args.arrival_distance,
  'stopping_speed': args.stopping_speed,
  'moving_speed': args.moving_speed,
}
coverage = from_corpus(args.SUT_inputs_path, config)
print(f'\nCoverage:')
coverage.print()

with open(f"src/scenariogen/predicates/{args.predicates_file}", 'r') as f:
  logic_program = f.read()

coverage_gap = coverage.predicate_gap(predicates_of_logic_program(logic_program))
print(f'\nCoverage gap:')
coverage_gap.print()
