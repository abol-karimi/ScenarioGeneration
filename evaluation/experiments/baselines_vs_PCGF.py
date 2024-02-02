#!/usr/bin/env python3.8

import evaluation.experiments.Atheris as Atheris_experiment
import evaluation.experiments.PCGF as PCGF_experiment
import evaluation.experiments.random_search as random_search_experiment
import evaluation.utils.experiment_runner
from evaluation.utils.utils import get_test_config
import evaluation.utils.events_to_coverage
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

  for trial_seed in trials_seeds:
    trial_output_folder = f'{output_folder}/Atheris/{gen_ego}_{gen_coverage}_{trial_seed}'
    gen_config = Atheris_experiment.get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, max_total_time, trial_output_folder)
    evaluation.utils.experiment_runner.run(gen_config)
    test_config = get_test_config(gen_config, test_ego,  test_coverage, max_total_time)
    evaluation.utils.events_to_coverage.report(test_config)

  for trial_seed in trials_seeds:
    trial_output_folder = f'{output_folder}/PCGF/{gen_ego}_{gen_coverage}_{trial_seed}'
    gen_config = PCGF_experiment.get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, max_total_time, trial_output_folder)
    evaluation.utils.experiment_runner.run(gen_config)
    test_config = get_test_config(gen_config, test_ego,  test_coverage, max_total_time)
    evaluation.utils.events_to_coverage.report(test_config)
    
  for trial_seed in trials_seeds:
    trial_output_folder = f'{output_folder}/random_search/{gen_ego}_{gen_coverage}_{trial_seed}'
    gen_config = random_search_experiment.get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, max_total_time, trial_output_folder)
    evaluation.utils.experiment_runner.run(gen_config)
    test_config = get_test_config(gen_config, test_ego,  test_coverage, max_total_time)
    evaluation.utils.events_to_coverage.report(test_config)

  # Plot the results
  # plot_configs = []
  # for plot in evaluation.utils.plots.baseline_plots:
  #   plot(plot_configs)

