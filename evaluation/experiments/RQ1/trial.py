#!/usr/bin/env python
import setproctitle
import argparse
from pathlib import Path
import importlib

import evaluation.utils.experiment_runner


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Run a trial for the PCGF-vs-baselines experiment.')
    parser.add_argument('--experiment', required=True,
                        help='the python module containing the experiment config')
    parser.add_argument('--ego',
                        help='the agent under test. Its performance is used as a feedback to generate more test-cases.')
    parser.add_argument('--randomizer-seed', type=int, default=0,
                        help='PRNG seed for the trial')
    parser.add_argument('--seeds-folder', required=True,
                        help='Fuzzing seeds folder')
    parser.add_argument('--coverage',
                        help='the scenic file containing coverage monitor')
    parser.add_argument('--seconds', type=float, required=True,
                        help='number of seconds to run the trial')
    parser.add_argument('--output-folder', required=True,
                        help='the base folder to store the results (fuzz-inputs, coverage, logs, etc.)')
    parser.add_argument('--process-name', default='RQ1',
                        help='the base folder to store the results (fuzz-inputs, coverage, logs, etc.)')
    args = parser.parse_args()

    setproctitle.setproctitle(args.process_name)

    experiment = importlib.import_module(f'evaluation.experiments.{args.experiment}')
    config = experiment.get_config(args.ego,
                                    args.coverage,
                                    args.randomizer_seed,
                                    args.seeds_folder,
                                    args.seconds,
                                    args.output_folder)

    # Run the experiment
    trial_output_path = Path(args.output_folder)
    trial_output_path.mkdir(parents=True, exist_ok=True)
    evaluation.utils.experiment_runner.run(config)
