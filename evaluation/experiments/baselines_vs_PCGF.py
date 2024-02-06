#!/usr/bin/env python3.8

from scenariogen.core.coverages.coverage import Predicate

import evaluation.experiments.Atheris as Atheris_experiment
import evaluation.experiments.PCGF as PCGF_experiment
import evaluation.experiments.random_search as random_search_experiment
import evaluation.utils.experiment_runner
from evaluation.utils.utils import get_test_config
import evaluation.utils.events_to_coverage
import evaluation.utils.average_coverage
import evaluation.utils.plots


if __name__ == '__main__':
  max_total_time = 8*60*60 # seconds
  gen_ego = 'TFPP'
  gen_coverage = 'traffic-rules'
  test_ego = gen_ego
  test_coverage = gen_coverage
  seeds_folder = 'evaluation/seeds/random/seeds'
  output_folder = f'evaluation/results/baselines_vs_PCGF'

  run_configs = [
    {'generator': 'PCGF',
     'experiment-module': PCGF_experiment,
     'trial-seeds': (4,),
     'max-total-time': max_total_time,
     },
  ]
  events2coverage_configs = [
    {'generator': 'PCGF',
     'experiment-module': PCGF_experiment,
     'trial-seeds': (4,),
     'max-total-time': max_total_time,
     },
  ]
  average_configs = [
    {'generator': 'PCGF',
     'experiment-module': PCGF_experiment,
     'trial-seeds': (4,),
     'max-total-time': max_total_time,
     'output-file': f'{output_folder}/PCGF/all-coverage.json',
     'statement-filter': lambda s: s,
     },
    {'generator': 'PCGF',
     'experiment-module': PCGF_experiment,
     'trial-seeds': (4,),
     'max-total-time': max_total_time,
     'output-file': f'{output_folder}/PCGF/violations-coverage.json',
     'statement-filter': lambda s:
                          s.predicate in {Predicate('violatesRule'),
                                          Predicate('violatesRightOfForRule'),
                                          Predicate('collidedWithAtTime')} \
                          and s.args[0] == 'ego',
     },
  ]

  coverage_plot_configs = [
    {
      'generators': ['PCGF', ],
      'coverage-types': ['statementSet', 'statement', 'predicateSet', 'predicate'],
      'PCGF': {'coverage-file': f'{output_folder}/PCGF/all-coverage.json',
                'color': 'g',
                'label': 'PCGF', 
              },
      'Atheris': {'coverage-file': f'{output_folder}/Atheris/all-coverage.json',
                  'color': 'r',
                  'label': 'Atheris',
                  },
      'random-search': {'coverage-file': f'{output_folder}/random_search/all-coverage.json',
                        'color': 'b',
                        'label': 'Random search',
                        },
      'output-file': f'{output_folder}/baselines-vs-PCGF_per-time.png',
     },
    {
      'generators': ['PCGF', ],
      'coverage-types': ['statementSet', 'statement', 'predicateSet', 'predicate'],
      'PCGF': {'coverage-file': f'{output_folder}/PCGF/violations-coverage.json',
                'color': 'g',
                'label': 'PCGF',
                },
      'Atheris': {'coverage-file': f'{output_folder}/Atheris/violations-coverage.json',
                  'color': 'r',
                  'label': 'Atheris',
                  },
      'random-search': {'coverage-file': f'{output_folder}/random_search/violations-coverage.json',
                        'color': 'b',
                        'label': 'Random search',
                        },
      'output-file': f'{output_folder}/baselines-vs-PCGF_violations_per-time.png',
    },
  ]


  # Run the experiments
  for config in run_configs:
    for trial_seed in config['trial-seeds']:
      trial_output_folder = f"{output_folder}/{config['generator']}/{gen_ego}_{gen_coverage}_{trial_seed}"
      gen_config = config['experiment-module'].get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, config['max-total-time'], trial_output_folder)
      evaluation.utils.experiment_runner.run(gen_config)

  # Compute coverages 
  for config in events2coverage_configs:
    for trial_seed in config['trial-seeds']:
      trial_output_folder = f"{output_folder}/{config['generator']}/{gen_ego}_{gen_coverage}_{trial_seed}"
      gen_config = config['experiment-module'].get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, config['max-total-time'], trial_output_folder)
      test_config = get_test_config(gen_config, test_ego, test_coverage, config['max-total-time'])
      evaluation.utils.events_to_coverage.report(test_config)

  # Combine the trials into one report
  for config in average_configs:
    test_configs = []
    for trial_seed in config['trial-seeds']:
      trial_output_folder = f"{output_folder}/{config['generator']}/{gen_ego}_{gen_coverage}_{trial_seed}"
      gen_config = config['experiment-module'].get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, config['max-total-time'], trial_output_folder)
      test_configs.append(get_test_config(gen_config, test_ego, test_coverage, config['max-total-time']))
    evaluation.utils.average_coverage.report(test_configs, config['statement-filter'], config['output-file'])


#-----------------------Plots-----------------------
  for plot in evaluation.utils.plots.coverage_plots:
    for config in coverage_plot_configs:
      plot(config)



