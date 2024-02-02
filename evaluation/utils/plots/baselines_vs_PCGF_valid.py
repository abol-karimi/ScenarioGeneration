#!/usr/bin/env python3.8

""" Generate the coverage reports """

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt


def plot(experiment_type, experiment_name, coverage_ego):
  coverage_file = f'experiments/{experiment_type}/output_{experiment_name}/coverage_{coverage_ego}.json'
  with open(coverage_file, 'r') as f:
    coverage = jsonpickle.decode(f.read())

  measurements = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                          coverage)['measurements']
  measurements = [m for m in measurements if 'statement_coverage' in m]
  exe_times = tuple(m['exe_time'] for m in measurements)
  new_fuzz_inputs = tuple(m['new_fuzz_inputs'] for m in measurements)
  new_valid_inputs = tuple(m['valid_inputs'] for m in measurements)

  exe_times_acc = [exe_times[0]]
  new_fuzz_inputs_acc = [new_fuzz_inputs[0]]
  new_valid_inputs_acc = [new_valid_inputs[0]]
  for i in range(1, len(measurements)):
    exe_times_acc.append(exe_times_acc[-1] + exe_times[i])
    new_fuzz_inputs_acc.append(new_fuzz_inputs_acc[-1].union(new_fuzz_inputs[i]))
    new_valid_inputs_acc.append(new_valid_inputs_acc[-1].union(new_valid_inputs[i]))

  ax1.plot(exe_times_acc, tuple(len(c) for c in new_fuzz_inputs_acc), 'b-')
  ax1.plot(exe_times_acc, tuple(len(c) for c in new_valid_inputs_acc), 'b-')


if __name__ == '__main__':
  reports_config = (
    ('random_search', 'autopilot', 'autopilot'),
    ('Atheris', 'autopilot', 'autopilot'),
  )
  fig_coverage = plt.figure()
  fig_coverage.suptitle(f'Random vs Coverage-Guided Fuzzing')

  ax = fig_coverage.add_subplot(111)    # The big subplot
  # Turn off axis lines and ticks of the big subplot
  ax.spines['top'].set_color('none')
  ax.spines['bottom'].set_color('none')
  ax.spines['left'].set_color('none')
  ax.spines['right'].set_color('none')
  ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)
  # Set common labels
  ax.set_xlabel('Wall-clock time (seconds)')

  ax1 = fig_coverage.add_subplot(111)
  ax1.set_ylabel('Count')

  for experiment_type, experiment_name, coverage_ego in reports_config:
    print(experiment_type, experiment_name, coverage_ego)
    plot(experiment_type, experiment_name, coverage_ego)

  plt.tight_layout()
  fig_coverage.savefig('experiments/ISSTA_plots/baseline-vs-CCGF_valid.png')