#!/usr/bin/env python3.8

import setproctitle
import argparse

import evaluation.experiments.Atheris as Atheris_experiment
import evaluation.experiments.PCGF as PCGF_experiment
import evaluation.experiments.Random as Random_experiment
import evaluation.utils.experiment_runner
from scenariogen.core.logger import Logger

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Run a trial for the PCGF-vs-baselines experiment.')
    parser.add_argument('--generator', choices=['PCGF', 'Atheris', 'Random'], default='PCGF',
                        help='the test-case generator')
    parser.add_argument('--ego',
                        help='the scenic file containing the ego scenario')
    parser.add_argument('--randomizer-seed', type=int, default=0,
                        help='PRNG seed for the trial')
    parser.add_argument('--seeds-folder', default='evaluation/seeds/random/seeds',
                        help='Fuzzing seeds folder')
    parser.add_argument('--coverage',
                        help='the scenic file containing coverage monitor')
    parser.add_argument('--seconds', type=float, default=60,
                        help='number of seconds to run the scenario')
    args = parser.parse_args()

    setproctitle.setproctitle(f'{args.generator}_{args.randomizer_seed}')

    g2e = {'PCGF': PCGF_experiment,
           'Atheris': Atheris_experiment,
           'Random': Random_experiment
           }
    experiment = g2e[args.generator]

    # Run the experiment
    trial_output_folder = f"evaluation/results/baselines_vs_PCGF/{args.generator}/{args.ego}_{args.coverage}_{args.randomizer_seed}"

    logger = Logger(f'{trial_output_folder}/trial.log', filemode='w')
    logger.start()

    gen_config = experiment.get_config(args.ego,
                                       args.coverage,
                                       args.randomizer_seed,
                                       args.seeds_folder,
                                       args.seconds,
                                       trial_output_folder)
    evaluation.utils.experiment_runner.run(gen_config)

    logger.stop()