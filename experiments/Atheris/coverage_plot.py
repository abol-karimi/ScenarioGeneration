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

with open(output_path/'coverage_report.json', 'r') as f:
  cov_statements = f.read(jsonpickle.decode(f.read()))
input2statementCoverage = from_corpus(output_path/'fuzz-inputs', config)
input2predicateSetCoverage = {i: c.to_predicateSetCoverage() for i,c in input2statementCoverage.items()}
input2predicateCoverage = {i: c.to_predicateCoverage() for i,c in input2statementCoverage.items()}

with open(output_path/'report.json', 'r') as f:
  report = jsonpickle.decode(f.read())

ts = [report[0][0]]
for exe_time, _, _ in report[1:]:
  ts.append(ts[-1] + exe_time)

cov_statement = [report[0][2]]
for _, _, new_fuzz_inputs in report[1:]:
  cov = cov_statement[-1]
  for path in new_fuzz_inputs:
    cov = cov + input2statementCoverage[path]
  cov_statement.append(cov)

plt.plot(ts, tuple(len(c) for c in cov_statement))
plt.plot(ts, tuple(len(c.to_predicateSetCoverage()) for c in cov_statement))
plt.plot(ts, tuple(len(c.to_predicateCoverage()) for c in cov_statement))
plt.show()