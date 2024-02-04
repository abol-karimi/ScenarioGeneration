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
  max_total_time = 4*60*60 # seconds
  gen_ego = 'TFPP'
  gen_coverage = 'traffic-rules'
  test_ego = gen_ego
  test_coverage = gen_coverage
  run_trials = (1,)
  events2coverage_trials = (1,)
  average_trials = (0, 1)
  seeds_folder = 'evaluation/seeds/random/seeds'
  output_folder = f'evaluation/results/baselines_vs_PCGF'

  coverage_plots_config = {
    'generators': ['PCGF', 'Atheris', 'random-search'],
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
  }
  
  violations_plots_config = {
    'generators': ['PCGF', 'Atheris', 'random-search'],
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
  }

  trials_seeds = sorted(set(run_trials + events2coverage_trials + average_trials))

  #-----------------------Atheris-----------------------
  gen_test_configs = []
  for trial_seed in trials_seeds:
    trial_output_folder = f'{output_folder}/Atheris/{gen_ego}_{gen_coverage}_{trial_seed}'
    gen_config = Atheris_experiment.get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, max_total_time, trial_output_folder)
    test_config = get_test_config(gen_config, test_ego,  test_coverage, max_total_time)
    gen_test_configs.append((gen_config, test_config))
 
  run_configs = [g for g,t in gen_test_configs if g['randomizer-seed'] in run_trials]
  for gen_config in run_configs:
    evaluation.utils.experiment_runner.run(gen_config)

  events2coverage_configs = [t for g,t in gen_test_configs if g['randomizer-seed'] in events2coverage_trials]
  for t in events2coverage_configs:
    evaluation.utils.events_to_coverage.report(t)
  
  average_configs = [(g, t) for g,t in gen_test_configs if g['randomizer-seed'] in average_trials]
  evaluation.utils.average_coverage.report(average_configs, coverage_plots_config['Atheris']['coverage-file'])
  evaluation.utils.average_violations.report(average_configs, violations_plots_config['Atheris']['coverage-file'])


  #-----------------------PCGF-----------------------
  gen_test_configs = []
  for trial_seed in trials_seeds:
    trial_output_folder = f'{output_folder}/PCGF/{gen_ego}_{gen_coverage}_{trial_seed}'
    gen_config = PCGF_experiment.get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, max_total_time, trial_output_folder)
    test_config = get_test_config(gen_config, test_ego,  test_coverage, max_total_time)
    gen_test_configs.append((gen_config, test_config))
 
  run_configs = [g for g,t in gen_test_configs if g['randomizer-seed'] in run_trials]
  for gen_config in run_configs:
    evaluation.utils.experiment_runner.run(gen_config)

  events2coverage_configs = [t for g,t in gen_test_configs if g['randomizer-seed'] in events2coverage_trials]
  for t in events2coverage_configs:
    evaluation.utils.events_to_coverage.report(t)
  
  average_configs = [(g, t) for g,t in gen_test_configs if g['randomizer-seed'] in average_trials]
  evaluation.utils.average_coverage.report(average_configs, coverage_plots_config['PCGF']['coverage-file'])
  evaluation.utils.average_violations.report(average_configs, violations_plots_config['PCGF']['coverage-file'])


  #-----------------------random search-----------------------
  gen_test_configs = []
  for trial_seed in trials_seeds:
    trial_output_folder = f'{output_folder}/random_search/{gen_ego}_{gen_coverage}_{trial_seed}'
    gen_config = random_search_experiment.get_config(gen_ego, gen_coverage, trial_seed, seeds_folder, max_total_time, trial_output_folder)
    test_config = get_test_config(gen_config, test_ego,  test_coverage, max_total_time)
    gen_test_configs.append((gen_config, test_config))
 
  run_configs = [g for g,t in gen_test_configs if g['randomizer-seed'] in run_trials]
  for gen_config in run_configs:
    evaluation.utils.experiment_runner.run(gen_config)

  events2coverage_configs = [t for g,t in gen_test_configs if g['randomizer-seed'] in events2coverage_trials]
  for t in events2coverage_configs:
    evaluation.utils.events_to_coverage.report(t)
  
  average_configs = [(g, t) for g,t in gen_test_configs if g['randomizer-seed'] in average_trials]
  evaluation.utils.average_coverage.report(average_configs, coverage_plots_config['random-search']['coverage-file'])
  evaluation.utils.average_violations.report(average_configs, violations_plots_config['random-search']['coverage-file'])


#-----------------------Plots-----------------------
  for plot in evaluation.utils.plots.coverage_plots:
    plot(coverage_plots_config, output_folder)

  for plot in evaluation.utils.plots.violations_plots:
    plot(violations_plots_config, output_folder)


