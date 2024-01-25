#!/usr/bin/env python3.8

# Run several experiments, populate results, plot the graphs

from experiments.random_search.experiment import config as random_search_config
from experiments.Atheris.experiment import config as Atheris_config
from experiments.PCGF.experiment import config as PCGF_config
from experiments.runner import run


if __name__ == '__main__':
  experiments = (
    (random_search_config, 'Random search'),
    (Atheris_config, 'Atheris'),
    (PCGF_config, 'PCGF'),
  )

  for config, experiment_name in experiments:
    print(f'Now running experiment: {experiment_name}')
    run(config)
