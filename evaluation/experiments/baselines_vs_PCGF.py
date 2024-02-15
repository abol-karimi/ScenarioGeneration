#!/usr/bin/env python3.8

import setproctitle

import evaluation.experiments.Atheris as Atheris_experiment
import evaluation.experiments.PCGF as PCGF_experiment
import evaluation.experiments.Random as Random_experiment
import evaluation.utils.experiment_runner
from evaluation.utils.utils import get_test_config
import evaluation.utils.events_to_coverage
import evaluation.utils.average_coverage
import evaluation.utils.plots
from evaluation.configs import ego_violations_coverage_filter


if __name__ == '__main__':
  setproctitle.setproctitle('baseline-vs-PCGF')

  max_total_time = 8*60*60 # seconds
  gen_ego = 'TFPP'
  gen_coverage = 'traffic-rules'
  test_ego = gen_ego
  test_coverage = gen_coverage
  seeds_folder = 'evaluation/seeds/random/seeds'
  output_folder = f'evaluation/results/baselines_vs_PCGF'

  run_configs = [
    # {'generator': 'PCGF',
    #  'experiment-module': PCGF_experiment,
    #  'trial-seeds': (0,1),
    #  'max-total-time': max_total_time,
    #  },
    # {'generator': 'Atheris',
    #  'experiment-module': Atheris_experiment,
    #  'trial-seeds': (0,1),
    #  'max-total-time': max_total_time,
    #  },
    # {'generator': 'Random',
    #  'experiment-module': Random_experiment,
    #  'trial-seeds': (0,1),
    #  'max-total-time': max_total_time,
    #  },
  ]
  average_configs = [
    # {'generator': 'PCGF',
    #  'experiment-module': PCGF_experiment,
    #  'trial-seeds': (0,1),
    #  'max-total-time': max_total_time,
    #  'output-file': f'{output_folder}/PCGF/all-coverage.json',
    #  'coverage-filter': lambda s: s,
    #  },
    # {'generator': 'PCGF',
    #  'experiment-module': PCGF_experiment,
    #  'trial-seeds': (0,1),
    #  'max-total-time': max_total_time,
    #  'output-file': f'{output_folder}/PCGF/violations-coverage.json',
    #  'coverage-filter': ego_violations_coverage_filter,
    #  },
    # {'generator': 'Atheris',
    #  'experiment-module': Atheris_experiment,
    #  'trial-seeds': (0,1),
    #  'max-total-time': max_total_time,
    #  'output-file': f'{output_folder}/Atheris/all-coverage.json',
    #  'coverage-filter': lambda s: s,
    #  },
    # {'generator': 'Atheris',
    #  'experiment-module': Atheris_experiment,
    #  'trial-seeds': (0,1),
    #  'max-total-time': max_total_time,
    #  'output-file': f'{output_folder}/Atheris/violations-coverage.json',
    #  'coverage-filter': ego_violations_coverage_filter,
    #  },
    # {'generator': 'Random',
    #  'experiment-module': Random_experiment,
    #  'trial-seeds': (0,1),
    #  'max-total-time': max_total_time,
    #  'output-file': f'{output_folder}/Random/all-coverage.json',
    #  'coverage-filter': lambda s: s,
    #  },
    # {'generator': 'Random',
    #  'experiment-module': Random_experiment,
    #  'trial-seeds': (0,1),
    #  'max-total-time': max_total_time,
    #  'output-file': f'{output_folder}/Random/violations-coverage.json',
    #  'coverage-filter': ego_violations_coverage_filter,
    #  },
  ]

  plot_configs = [
    {
      'generators': ['PCGF', 'Atheris', 'Random'],
      'coverage-types': ['statementSet', 'statement', 'predicateSet', 'predicate'],
      'PCGF': {'coverage-file': f'{output_folder}/PCGF/all-coverage.json',
                'color': 'g',
                'label': 'PCGF', 
              },
      'Atheris': {'coverage-file': f'{output_folder}/Atheris/all-coverage.json',
                  'color': 'b',
                  'label': 'Atheris',
                  },
      'Random': {'coverage-file': f'{output_folder}/Random/all-coverage.json',
                  'color': 'r',
                  'label': 'Random',
                  },
      'plotter': evaluation.utils.plots.baselines_vs_PCGF_per_time,
      'output-file': f'{output_folder}/baselines-vs-PCGF_per-time.png',
    },
    {
      'generators': ['PCGF', 'Atheris', 'Random'],
      'coverage-types': ['statementSet', 'statement', 'predicateSet', 'predicate'],
      'PCGF': {'coverage-file': f'{output_folder}/PCGF/violations-coverage.json',
                'color': 'g',
                'label': 'PCGF',
                },
      'Atheris': {'coverage-file': f'{output_folder}/Atheris/violations-coverage.json',
                  'color': 'b',
                  'label': 'Atheris',
                  },
      'Random': {'coverage-file': f'{output_folder}/Random/violations-coverage.json',
                  'color': 'r',
                  'label': 'Random',
                  },
      'plotter': evaluation.utils.plots.baselines_vs_PCGF_per_time,
      'output-file': f'{output_folder}/baselines-vs-PCGF_violations_per-time.png',
    },
    {
      'generators': ['PCGF', 'Atheris', 'Random'],
      'coverage-types': ['statementSet', 'statement', 'predicateSet', 'predicate'],
      'PCGF': {'coverage-file': f'{output_folder}/PCGF/all-coverage.json',
                'color': 'g',
                'label': 'PCGF', 
              },
      'Atheris': {'coverage-file': f'{output_folder}/Atheris/all-coverage.json',
                  'color': 'b',
                  'label': 'Atheris',
                  },
      'Random': {'coverage-file': f'{output_folder}/Random/all-coverage.json',
                  'color': 'r',
                  'label': 'Random',
                  },
      'plotter': evaluation.utils.plots.baselines_vs_PCGF_per_fuzz_input,
      'output-file': f'{output_folder}/baselines-vs-PCGF_per-fuzz-input.png',
    },
    {
      'generators': ['PCGF', 'Atheris', 'Random'],
      'coverage-types': ['statementSet', 'statement', 'predicateSet', 'predicate'],
      'PCGF': {'coverage-file': f'{output_folder}/PCGF/violations-coverage.json',
                'color': 'g',
                'label': 'PCGF',
                },
      'Atheris': {'coverage-file': f'{output_folder}/Atheris/violations-coverage.json',
                  'color': 'b',
                  'label': 'Atheris',
                  },
      'Random': {'coverage-file': f'{output_folder}/Random/violations-coverage.json',
                  'color': 'r',
                  'label': 'Random',
                  },
      'plotter': evaluation.utils.plots.baselines_vs_PCGF_per_fuzz_input,
      'output-file': f'{output_folder}/baselines-vs-PCGF_violations_per-fuzz-input.png',
    },
  ]


  # Run the experiments
  for config in run_configs:
    for trial_seed in config['trial-seeds']:
      trial_output_folder = f"{output_folder}/{config['generator']}/{gen_ego}_{gen_coverage}_{trial_seed}"
      gen_config = config['experiment-module'].get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, config['max-total-time'], trial_output_folder)
      evaluation.utils.experiment_runner.run(gen_config)

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



