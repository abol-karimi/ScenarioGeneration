#!/usr/bin/env python3.8
import argparse
from functools import reduce
from scenariogen.core.coverages.coverage import from_corpus, StatementCoverage
from scenariogen.predicates.utils import predicates_of_logic_program
from experiments.configs import SUT_config, coverage_config

parser = argparse.ArgumentParser(
    description='Compute the predicate coverage of a corpus of SUT inputs.')
parser.add_argument('SUT_inputs_path',
                    help='relative path of the corpus folder')
parser.add_argument('--ego_module',
                    default='experiments.agents.autopilot',
                    help='the scenic file containing the ego scenario')
args = parser.parse_args()

config = {
  **SUT_config,
  **coverage_config,
  'ego_module': args.ego_module,
  'coverage_module': 'scenariogen.core.coverages.traffic',
}
results = from_corpus(args.SUT_inputs_path, config)
seed2statementCoverage = results[0]
nonego_collisions = results[1]
ego_collisions = results[2]
simulation_creation_errors = results[3]
simulation_rejections = results[4]
none_coverages = results[5]

coverage = reduce(lambda c1,c2: c1+c2,
                            list(seed2statementCoverage.values()),
                            StatementCoverage([]))
print(f'\nCoverage:')
coverage.print()

traffic_rules_file = '4way-stopOnAll.lp'
predicate_files = (f'src/scenariogen/predicates/{traffic_rules_file}',
                    'src/scenariogen/predicates/traffic.lp',
                )
encoding = ''
for file_path in predicate_files:
    with open(file_path, 'r') as f:
        encoding += f.read()
predicate_coverage_space = predicates_of_logic_program(encoding)
coverage_gap = predicate_coverage_space - coverage.to_predicateCoverage()
print(f'\nPredicate coverage gap:')
coverage_gap.print()

print(f'\nnonego_collisions: {nonego_collisions}')
print(f'\nego_collisions: {ego_collisions}')
print(f'\nsimulation_creation_errors: {simulation_creation_errors}')
print(f'\nsimulation_rejections: {simulation_rejections}')
print(f'\nnone_coverages: {none_coverages}')