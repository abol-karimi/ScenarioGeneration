#!/usr/bin/env python3

from pathlib import Path
import jsonpickle
from functools import reduce
import matplotlib.pyplot as plt
import importlib
from collections import Counter
import numpy as np
import statistics

from scenariogen.core.coverages.coverage import StatementCoverage
from evaluation.configs import ego_violations_coverage_filter
from evaluation.utils.utils import to_StatementSetCoverage


def plot(trials_folders, predicate_coverage_space, output_file, width=0.5):
    fig_coverage = plt.figure(layout='constrained', figsize=(10, 6))

    ax = fig_coverage.add_subplot(111)
    ax.set_xlabel('Predicate')
    ax.set_ylabel('Frequency distribution over the trials')
    # ax.set_yscale('log')

    pred2counts = {p: [] for p in predicate_coverage_space.items}
    for trial_folder in trials_folders:
        coverage_files = Path(f'{trial_folder}/coverages').glob('*')
        
        statementCoverage = to_StatementSetCoverage(coverage_files, ego_violations_coverage_filter).cast_to(StatementCoverage)
        count = Counter(statement.predicate for statement in statementCoverage.items)

        for p in predicate_coverage_space.items:
            pred2counts[p].append(count[p])

    # Create a boxplot for each predicate
    predicates_sorted = sorted(predicate_coverage_space.items,
                               reverse=True,
                               key=lambda p: statistics.median(pred2counts[p]))
    x = np.arange(len(predicates_sorted))*2  # the label locations
    ax.set_xticks(x, [str(p) for p in predicates_sorted])

    ax.boxplot([pred2counts[p] for p in predicates_sorted], positions=x, widths=width)

    plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
    fig_coverage.savefig(output_file)


if __name__ == '__main__':
  
    # the x-axis domain is the predicate coverage_measurements space
    fuzz_inputs_path = Path(f'evaluation/results/RQ1/Random_autopilot_traffic-rules/0/fuzz-inputs')
    with open(tuple(fuzz_inputs_path.glob('*'))[0], 'r') as f:
        fuzz_input = jsonpickle.decode(f.read())
    coverage_module = importlib.import_module(f'scenariogen.core.coverages.traffic-rules')
    predicate_coverage_space = coverage_module.coverage_space(fuzz_input.config)

    reports_config = (
        ('Random', 'autopilot', 'traffic-rules', ),
    )

    for experiment, ego, coverage in reports_config:
        print(f'Now plotting report: {experiment, ego, coverage}')
        trials_folders = [f'evaluation/results/RQ1/{experiment}_{ego}_{coverage}/{i}'
                            for i in range(10)]
        output_file = f'evaluation/results/RQ1/{experiment}_{ego}_{coverage}/predicate-distribution.png'
        plot(trials_folders, predicate_coverage_space, output_file)
  
