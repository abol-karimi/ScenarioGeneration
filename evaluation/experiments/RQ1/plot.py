#!/usr/bin/env python3

import setproctitle
from itertools import product

import evaluation.experiments.Atheris as Atheris_experiment
import evaluation.experiments.PCGF as PCGF_experiment
import evaluation.experiments.Random as Random_experiment
import evaluation.utils.experiment_runner
from evaluation.utils.utils import get_test_config
import evaluation.utils.events_to_coverage
import evaluation.utils.average_coverage
import evaluation.utils.plots
import evaluation.utils.plots.baselines_vs_PCGF_per_time
import evaluation.utils.plots.baselines_vs_PCGF_per_fuzz_input
from evaluation.configs import ego_violations_coverage_filter


if __name__ == '__main__':
  setproctitle.setproctitle('Plot')

  generators = ('PCGF', 'Random')
  trial_seeds = (0, 1, 2, 3, 4)
  gen_ego = 'TFPP'
  gen_coverage = 'traffic-rules'
  test_ego = gen_ego
  test_coverage = gen_coverage
  seeds_folder = 'evaluation/seeds/random/seeds'
  max_total_time = 12*60*60 # seconds
  output_folder = f'evaluation/results/RQ1'

  coverage_filters = ('all', 'violations')
  normalizers = ('per-time', 'per-fuzz-input')

  filter_to_func = {
    'all': lambda s: s,
    'violations': ego_violations_coverage_filter,
  }
  g2e = {
    'PCGF': PCGF_experiment,
    'Atheris': Atheris_experiment,
    'Random': Random_experiment
  }
  average_configs = [
    {
      'generator': gen,
      'experiment-module': g2e[gen],
      'trial-seeds': trial_seeds,
      'max-total-time': max_total_time,
      'output-file': f'{output_folder}/{gen}/{cov_filter}-coverage.json',
      'coverage-filter': filter_to_func[cov_filter],
    } for gen, cov_filter in product(generators, coverage_filters)
  ] 
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

  # Average the trials
  for config in average_configs:
    test_configs = []
    for trial_seed in config['trial-seeds']:
      trial_output_folder = f"{output_folder}/{config['generator']}/{gen_ego}_{gen_coverage}_{trial_seed}"
      gen_config = config['experiment-module'].get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, config['max-total-time'], trial_output_folder)
      test_configs.append(get_test_config(gen_config, test_ego, test_coverage, config['max-total-time']))
    evaluation.utils.average_coverage.report(test_configs, config['coverage-filter'], config['output-file'])

  # Plot the results
  for config in plot_configs:
    config['plotter'].plot(config)



