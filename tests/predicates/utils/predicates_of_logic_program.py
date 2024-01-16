#!/usr/bin/env python3.8

from scenariogen.predicates.utils import predicates_of_logic_program
from scenariogen.core.coverages.coverage import PredicateCoverage

print('Hi!')
traffic_rules_file = '4way-stopOnAll.lp'
logic_files = (f'src/scenariogen/predicates/{traffic_rules_file}',
                'src/scenariogen/predicates/traffic.lp',
              )
encoding = ''
for file_path in logic_files:
  with open(file_path, 'r') as f:
    encoding += f.read()
print(encoding)
predicate_coverage_space = PredicateCoverage(predicates_of_logic_program(encoding))
predicate_coverage_space.print()