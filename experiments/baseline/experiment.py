#!/usr/bin/env python3.8

from experiments.PCGF.experiment import get_config as PCGF_get_config
import experiments.runner
from experiments.test import get_test_config
import experiments.events_to_coverage
import experiments.ISSTA


if __name__ == '__main__':
  plot_configs = []

  baseline_total_time = 4*60*60
  gen_ego = 'TFPP'
  gen_coverage = 'traffic-rules'
  randomizer_seed = 0
  output_folder = f'experiments/PCGF/{gen_ego}_{gen_coverage}'
  gen_config = PCGF_get_config(gen_ego, gen_coverage, randomizer_seed, baseline_total_time, output_folder)
  test_config = get_test_config(gen_config, gen_ego, gen_coverage, baseline_total_time)
  plot_configs.append((gen_config, test_config, 'b', 'Atheris'))

  # Generate open-loop for 60 minutes, test with TFPP till baseline_total_time
  gen_ego = None
  gen_coverage = 'traffic-rules'
  randomizer_seed = 0
  max_total_time = 60*60 # 1 hour
  output_folder = f'experiments/PCGF/{gen_ego}_{gen_coverage}_{randomizer_seed}_{max_total_time}'
  gen_config = PCGF_get_config(gen_ego, gen_coverage, randomizer_seed, max_total_time, output_folder)
  # experiments.runner.run(gen_config)

  test_ego = 'TFPP'
  test_coverage = 'traffic-rules'
  max_total_time =  baseline_total_time - gen_config['max-total-time']
  test_config = get_test_config(gen_config, test_ego, test_coverage, max_total_time)
  # experiments.runner.run(test_config)
  # experiments.events_to_coverage.report(test_config)

  plot_configs.append((gen_config, test_config, 'r', 'open-loop surrogate'))


  # Generate with autopilot for 90 minutes, test with TFPP till baseline_total_time
  gen_ego = 'autopilot'
  gen_coverage = 'traffic-rules'
  randomizer_seed = 0
  max_total_time = 90*60 # 1 hour
  output_folder = f'experiments/PCGF/{gen_ego}_{gen_coverage}_{randomizer_seed}_{max_total_time}'
  gen_config = PCGF_get_config(gen_ego, gen_coverage, randomizer_seed, max_total_time, output_folder)
  # experiments.runner.run(gen_config)

  test_ego = 'TFPP'
  test_coverage = 'traffic-rules'
  max_total_time =  baseline_total_time - gen_config['max-total-time']
  test_config = get_test_config(gen_config, test_ego, test_coverage, max_total_time)
  experiments.runner.run(test_config)
  experiments.events_to_coverage.report(test_config)

  plot_configs.append((gen_config, test_config, 'g', 'autopilot surrogate'))

  for plot in experiments.ISSTA.surrogate_plots:
    plot(plot_configs)

