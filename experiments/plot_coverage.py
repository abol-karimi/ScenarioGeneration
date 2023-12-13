#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt

from scenariogen.predicates.utils import predicates_of_logic_program

def plot(experiment_type, experiment_name, coverage_ego, coverage):
  output_folder = f"experiments/{experiment_type}/output_{experiment_name}"
  output_path = Path(output_folder)
  coverage_file = output_path/f"coverage_{coverage_ego}.json"

  with open(coverage_file, 'r') as f:
    results = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                          results)['measurements']
  measurements = [m for m in measurements if 'statement_coverage' in m]
  exe_times = tuple(m['exe_time'] for m in measurements)
  statement_coverages = tuple(m['statement_coverage'] for m in measurements)
  for m in measurements:
    m['statement_coverage'].pred2args = {pred:args for pred,args in m['statement_coverage'].pred2args.items()
                                         if not (pred.endswith('AtTime') or pred == 'changedSignalBetween')}

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

  fig = plt.figure()
  fig.suptitle(f'Experiment type: {experiment_type},\n Experiment ego: {experiment_name},\n Coverage ego: {coverage_ego}')

  ax = fig.add_subplot(111)    # The big subplot
  # Turn off axis lines and ticks of the big subplot
  ax.spines['top'].set_color('none')
  ax.spines['bottom'].set_color('none')
  ax.spines['left'].set_color('none')
  ax.spines['right'].set_color('none')
  ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)
  # Set common labels
  ax.set_xlabel('Wall-clock time (seconds)')

  ax1 = fig.add_subplot(311)
  ax2 = fig.add_subplot(312)
  ax3 = fig.add_subplot(313)

  ax1.set_ylabel('Statements')
  ax1.plot(exe_times_acc, tuple(len(c) for c in statement_coverages_acc), 'b-')

  ax2.set_ylabel('Predicate-Sets')
  ax2.plot(exe_times_acc, tuple(len(c) for c in predicateSet_coverages_acc), 'b-')

  ax3.set_ylabel('Predicates')
  predicates_file = '4way-stopOnAll.lp'
  with open(f"src/scenariogen/predicates/{predicates_file}", 'r') as f:
    logic_program = f.read()
  predicate_coverage_space = predicates_of_logic_program(logic_program)
  plt.sca(ax3)
  ax3.plot(exe_times_acc, tuple(len(predicate_coverage_space) for c in range(len(exe_times_acc))), 'r--')
  ax3.plot(exe_times_acc, tuple(len(c & predicate_coverage_space) for c in predicate_coverages_acc), 'b-')

  plt.tight_layout()
  plt.savefig(output_path/f'coverage_{coverage_ego}_{coverage}.png')

if __name__ == '__main__':
  reports_config = (
    # ('Atheris', 'autopilot', 'autopilot', 'traffic'),
    # ('Atheris', 'autopilot', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'BehaviorAgent', 'autopilot', 'traffic'),
    # ('Atheris', 'BehaviorAgent', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'intersectionAgent', 'autopilot', 'traffic'),
    # ('Atheris', 'intersectionAgent', 'BehaviorAgent', 'traffic'),
    # ('Atheris', 'openLoop', 'autopilot', 'traffic'),
    # ('Atheris', 'openLoop', 'BehaviorAgent', 'traffic'),
    ('random_search', 'autopilot', 'autopilot', 'traffic'),
    # ('random_search', '4way-stop_autopilot', 'BehaviorAgent', 'traffic'),
  )

  for experiment_type, experiment_name, coverage_ego, coverage in reports_config:
    plot(experiment_type, experiment_name, coverage_ego, coverage)