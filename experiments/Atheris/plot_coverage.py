#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt

from experiments.configs import SUT_config, coverage_config
from scenariogen.predicates.utils import predicates_of_logic_program

fuzzing_ego = 'BehaviorAgent'
coverage_ego = 'BehaviorAgent'

output_folder = f'experiments/Atheris/output_{fuzzing_ego}'
output_path = Path(output_folder)
coverage_file = output_path/f"coverage_{coverage_ego if coverage_ego else 'openLoop'}.json"

config = {
  **SUT_config,
  **coverage_config,
}

with open(coverage_file, 'r') as f:
  results = jsonpickle.decode(f.read())

measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                        results)['measurements']
exe_times = tuple(m['exe_time'] for m in measurements)
statement_coverages = tuple(m['statement_coverage'] for m in measurements)
predicateSet_coverages = tuple(c.to_predicateSetCoverage() for c in statement_coverages)
predicate_coverages = tuple(c.to_predicateCoverage() for c in statement_coverages)

exe_times_acc = [exe_times[0]]
statement_coverages_acc = [statement_coverages[0]]
predicateSet_coverages_acc = [predicateSet_coverages[0]]
predicate_coverages_acc = [predicate_coverages[0]]
for i in range(1, len(measurements)):
  exe_times_acc.append(exe_times_acc[-1] + exe_times[i])
  statement_coverages_acc.append(statement_coverages_acc[-1] + statement_coverages[i])
  predicateSet_coverages_acc.append(predicateSet_coverages_acc[-1] + predicateSet_coverages[i])
  predicate_coverages_acc.append(predicate_coverages_acc[-1] + predicate_coverages[i])  

fig, axs = plt.subplots(3)
fig.suptitle('Coverage progress.')

axs[0].set_title('Statement Coverage')
axs[0].plot(exe_times_acc, tuple(len(c) for c in statement_coverages_acc), 'go')
axs[0].plot(exe_times_acc, tuple(len(c) for c in statement_coverages_acc), 'b-')

axs[1].set_title('Predicate-Set Coverage')
axs[1].plot(exe_times_acc, tuple(len(c) for c in predicateSet_coverages_acc), 'go')
axs[1].plot(exe_times_acc, tuple(len(c) for c in predicateSet_coverages_acc), 'b-')

axs[2].set_title('Predicate Coverage')
predicates_file = '4way-stopOnAll.lp'
with open(f"src/scenariogen/predicates/{predicates_file}", 'r') as f:
  logic_program = f.read()
predicate_coverage_space = predicates_of_logic_program(logic_program)
plt.sca(axs[2])
plt.yticks(range(len(predicate_coverage_space)+1))
axs[2].plot(exe_times_acc, tuple(len(predicate_coverage_space) for c in range(len(exe_times_acc))), 'r--')
axs[2].plot(exe_times_acc, tuple(len(c & predicate_coverage_space) for c in predicate_coverages_acc), '-o', c='blue', mfc='green', mec='green')
plt.show()