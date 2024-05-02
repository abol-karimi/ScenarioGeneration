#!/usr/bin/env python3

from itertools import product

import evaluation.utils.plots.baselines_vs_PCGF_per_time
import evaluation.utils.plots.baselines_vs_PCGF_per_fuzz_input


if __name__ == '__main__':

  generators = ('PCGF', 'Atheris', 'Random')
  output_folder = f'evaluation/results/RQ1'

  coverage_filters = ('all', 'violations')
  normalizers = ('per-time', 'per-fuzz-input')

  norm2plotter = {
    'per-time': evaluation.utils.plots.baselines_vs_PCGF_per_time,
    'per-fuzz-input': evaluation.utils.plots.baselines_vs_PCGF_per_fuzz_input
  }

  plot_configs = [
    {
      'generators': generators,
      'coverage-types': ('statementSet', 'statement', 'predicateSet', 'predicate'),
      'PCGF':
        {'coverage-file': f'{output_folder}/PCGF/{cov_filter}-coverage.json',
         'color': 'g',
         'label': 'PCGF',
        },
      'Atheris':
        {'coverage-file': f'{output_folder}/Atheris/{cov_filter}-coverage.json',
         'color': 'b',
         'label': 'Atheris',
        },
      'Random':
        {'coverage-file': f'{output_folder}/Random/{cov_filter}-coverage.json',
         'color': 'r',
         'label': 'Random',
        },
      'plotter': norm2plotter[norm],
      'output-file': f'{output_folder}/{cov_filter}-{norm}.png',
    } for norm, cov_filter in product(normalizers, coverage_filters)
  ]

  # Plot the results
  for config in plot_configs:
    config['plotter'].plot(config)



