#!/usr/bin/env python
import setproctitle
import argparse
from pathlib import Path

import evaluation.experiments.Test as Test_experiment
import evaluation.utils.experiment_runner


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Run a trial for the PCGF-vs-baselines experiment.')
    parser.add_argument('--ego',
                        help='the agent under test')
    parser.add_argument('--seeds-folder', required=True,
                        help='the test-case corpus')
    parser.add_argument('--coverage',
                        help='the coverage monitor to compute the coverage of the test-case corpus')
    parser.add_argument('--seconds', type=float, required=True,
                        help='number of seconds to run the trial')
    parser.add_argument('--output-folder', required=True,
                        help='the generator used to generate the test-case corpus')
    args = parser.parse_args()

    setproctitle.setproctitle(f'RQ2_{args.output_folder}_{args.ego}')

    # Run the experiment
    trial_output_path = Path(args.output_folder)
    trial_output_path.mkdir(parents=True, exist_ok=True)

    config = Test_experiment.get_config(args.ego,
                                       args.coverage,
                                       args.seeds_folder,
                                       args.seconds,
                                       args.output_folder)
    evaluation.utils.experiment_runner.run(config)
