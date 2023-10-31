#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
import matplotlib.pyplot as plt

from experiments.agents.configs import VUT_config
from experiments.configs import SUT_config, coverage_config
from scenariogen.core.coverages.coverage import from_corpus


output_folder = 'experiments/Atheris/output'
output_path = Path(output_folder)
report_file = output_path/'report.json'

config = {
  **SUT_config,
  **coverage_config,
}

input2statementCoverage = from_corpus(output_path/'fuzz-inputs', config)

with open(output_path/'report.json', 'r') as f:
  report = jsonpickle.decode(f.read())

for exe_time, _, new_fuzz_inputs in report[1:]:
  ts.append(ts[-1] + exe_time)

cov_statements = [report[0][2]]
for _, _, new_fuzz_inputs in report[1:]:
  cov = cov_statements[-1]
  for path in new_fuzz_inputs:
    cov = cov + input2statementCoverage[path]
  cov_statements.append(cov)

with open(output_path/'coverage_report.json', 'w') as f:
  f.write(jsonpickle.encode(cov_statements))

# predicates_file = '4way-stopOnAll.lp'
# with open(f"src/scenariogen/predicates/{predicates_file}", 'r') as f:
#   logic_program = f.read()

# coverage_gap = coverage.predicate_gap(predicates_of_logic_program(logic_program))
# print(f'\nCoverage gap:')
# coverage_gap.print()