#!/usr/bin/env python3

import subprocess
from itertools import product
from datetime import timedelta
import os

experiments = ('Random', 'Atheris', 'PCGF', )
egos = ('autopilot', 'BehaviorAgent', 'TFPP')
seeds_folder = 'evaluation/seeds/random/seeds'
randomizer_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, )
coverages = ('traffic-rules', )
trial_timeout = timedelta(hours=24)
timeout_buffer = timedelta(minutes=30)


# dependent variables
slurm_timeout = trial_timeout + timeout_buffer
trials = product(experiments, egos, randomizer_seeds, coverages)
dd = slurm_timeout.days
hh = slurm_timeout.seconds//3600
mm = (slurm_timeout.seconds%3600)//60
ss = slurm_timeout.seconds%60
STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')

for experiment, ego, randomizer_seed, coverage in trials:
    cmd = f'''
        sbatch \
        --mail-type=FAIL \
        --mail-user=ak@cs.unc.edu \
        --job-name=RQ1_{experiment}_{ego}_{randomizer_seed}_{coverage} \
        -o "%x_%j_%N.log" \
        --nodes=1 \
        --ntasks=1 \
        --cpus-per-task=8 \
        --mem=40G \
        --qos gpu_access \
        -p volta-gpu \
        --gres=gpu:tesla_v100-sxm2-16gb:1 \
        -t {dd}-{hh}:{mm}:{ss} \
        --wrap="\
            module add apptainer/1.3.0-1; \
            {STORE_BASE_DIR}/ScenarioGeneration/Apptainer/scripts.sh scenariogen_run bionic Shipping \
                evaluation/experiments/RQ1/trial.py \
                    --experiment {experiment} \
                    --ego {ego} \
                    --randomizer-seed {randomizer_seed} \
                    --seeds-folder {seeds_folder} \
                    --coverage {coverage} \
                    --seconds {trial_timeout.total_seconds()} \
                    --output-folder evaluation/results/RQ1/{experiment}/{ego}_{coverage}_{randomizer_seed} \
                    --process-name RQ1_{experiment}_{ego}_{randomizer_seed}
            "
    '''
    subprocess.Popen(cmd, shell=True)

