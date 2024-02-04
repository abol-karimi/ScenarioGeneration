#!/usr/bin/env python3.8

import evaluation.experiments.Atheris as Atheris_experiment
import evaluation.experiments.PCGF as PCGF_experiment
import evaluation.experiments.random_search as random_search_experiment
import evaluation.utils.experiment_runner
from evaluation.utils.utils import get_test_config
import evaluation.utils.events_to_coverage
import evaluation.utils.average_coverage
import evaluation.utils.average_violations
import evaluation.utils.plots


if __name__ == '__main__':
  max_total_time = 60*60 # seconds
  gen_ego = 'TFPP'
  gen_coverage = 'traffic-rules'
  test_ego = gen_ego
  test_coverage = gen_coverage
  trials_seeds = (2, 3)
  experiment_names = ('Atheris', 'PCGF', 'random_search')
  seeds_folder = 'evaluation/seeds/random/seeds'
  output_folder = f'evaluation/results/baselines_vs_PCGF'
  plot_config = {
    'coverage-configs': [
      {'coverage-file': f'{output_folder}/PCGF/all-coverage.json',
        'color': 'g',
        'label': 'PCGF',
        },
      {'coverage-file': f'{output_folder}/Atheris/all-coverage.json',
        'color': 'r',
        'label': 'Atheris',
        },
      # {'coverage-file': f'{output_folder}/random_search/all-coverage.json',
      #   'color': 'b',
      #   'label': 'Random search',
      #   },
    ],
    'violations-configs': [
      {'coverage-file': f'{output_folder}/PCGF/violations-coverage.json',
        'color': 'g',
        'label': 'PCGF',
        },
      {'coverage-file': f'{output_folder}/Atheris/violations-coverage.json',
        'color': 'r',
        'label': 'Atheris',
        },
      # {'coverage-file': f'{output_folder}/random_search/violations-coverage.json',
      #   'color': 'b',
      #   'label': 'Random search',
      #   },
    ],
    'output-folder': output_folder,
  }

  trials = []
  for trial_seed in trials_seeds:
    trial_output_folder = f'{output_folder}/Atheris/{gen_ego}_{gen_coverage}_{trial_seed}'
    gen_config = Atheris_experiment.get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, max_total_time, trial_output_folder)
    # evaluation.utils.experiment_runner.run(gen_config)
    test_config = get_test_config(gen_config, test_ego,  test_coverage, max_total_time)
    # evaluation.utils.events_to_coverage.report(test_config)
    trials.append((gen_config, test_config))
  # evaluation.utils.average_coverage.report(trials, plot_config['coverage-configs'][1]['coverage-file'])
  # evaluation.utils.average_violations.report(trials, plot_config['violations-configs'][1]['coverage-file'])
    
  trials = []
  for trial_seed in trials_seeds:
    trial_output_folder = f'{output_folder}/PCGF/{gen_ego}_{gen_coverage}_{trial_seed}'
    gen_config = PCGF_experiment.get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, max_total_time, trial_output_folder)
    # evaluation.utils.experiment_runner.run(gen_config)
    test_config = get_test_config(gen_config, test_ego,  test_coverage, max_total_time)
    # evaluation.utils.events_to_coverage.report(test_config)
    trials.append((gen_config, test_config))
  # evaluation.utils.average_coverage.report(trials, plot_config['coverage-configs'][0]['coverage-file'])
  # evaluation.utils.average_violations.report(trials, plot_config['violations-configs'][0]['coverage-file'])

  trials = []
  for trial_seed in trials_seeds:
    trial_output_folder = f'{output_folder}/random_search/{gen_ego}_{gen_coverage}_{trial_seed}'
    gen_config = random_search_experiment.get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, max_total_time, trial_output_folder)
    # evaluation.utils.experiment_runner.run(gen_config)
    test_config = get_test_config(gen_config, test_ego,  test_coverage, max_total_time)
    # evaluation.utils.events_to_coverage.report(test_config)
    trials.append((gen_config, test_config))
  # evaluation.utils.average_coverage.report(trials, plot_config['coverage-configs'][2]['coverage-file'])
  # evaluation.utils.average_violations.report(trials, plot_config['violations-configs'][2]['coverage-file'])

  # Plot the results
  for plot in evaluation.utils.plots.baseline_plots:
    plot(plot_config)

