#!/usr/bin/env python
import setproctitle
import argparse
from pathlib import Path

import evaluation.experiments.Atheris as Atheris_experiment
import evaluation.experiments.PCGF as PCGF_experiment
import evaluation.experiments.Random as Random_experiment
import evaluation.utils.experiment_runner
import scenariogen.core.logging.server as log_server

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Run a trial for the PCGF-vs-baselines experiment.')
    parser.add_argument('--generator', choices=['PCGF', 'Atheris', 'Random'], default='PCGF',
                        help='the test-case generator')
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
    args = parser.parse_args()

    setproctitle.setproctitle(f'RQ1_{args.generator}_{args.ego}_{args.randomizer_seed}')

    g2e = {'PCGF': PCGF_experiment,
           'Atheris': Atheris_experiment,
           'Random': Random_experiment
           }
    experiment = g2e[args.generator]

    # Run the experiment
    trial_output_path = Path(args.output_folder)
    trial_output_path.mkdir(parents=True, exist_ok=True)

    trial_log_path = trial_output_path / 'logs'
    trial_log_path.mkdir(parents=True, exist_ok=True)

    log_server.start(trial_log_path / 'trial.log', filemode='w')

    gen_config = experiment.get_config(args.ego,
                                       args.coverage,
                                       args.randomizer_seed,
                                       args.seeds_folder,
                                       args.seconds,
                                       args.output_folder)
    evaluation.utils.experiment_runner.run(gen_config)

    log_server.stop()