#!/usr/bin/env python3

import subprocess
from itertools import product
from datetime import timedelta
import os


baseline_experiment = 'PCGF'
baseline_egos = ('TFPP', )
baseline_coverages = ('traffic-rules', )
baseline_dir = f'evaluation/results/RQ1'

test_experiment = 'PCGF_precheck'
test_egos = (None, )
test_coverages = ('trivial', )
test_dir = f'evaluation/results/RQ3'

seeds_folder = 'evaluation/seeds/random/seeds'
randomizer_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, )
coverages = ('traffic-rules', )
trial_timeout = timedelta(hours=24)
timeout_buffer = timedelta(minutes=30)

# dependent variables
baselines = product(baseline_egos, baseline_coverages)
tests = product(test_egos, test_coverages)
trials = product(baselines, tests, randomizer_seeds)

slurm_timeout = trial_timeout + timeout_buffer
dd = slurm_timeout.days
hh = slurm_timeout.seconds//3600
mm = (slurm_timeout.seconds%3600)//60
ss = slurm_timeout.seconds%60
STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')

for baseline, test, trial in trials:
    (baseline_ego, baseline_coverage), (test_ego, test_coverage), randomizer_seed = trial
    cmd = f'''
        sbatch \
        --mail-type=FAIL \
        --mail-user=ak@cs.unc.edu \
        --job-name=RQ3_{test_experiment}_{test_ego}_{test_coverage}_{randomizer_seed} \
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
                evaluation/experiments/RQ3/trial.py \
                    --experiment {test_experiment} \
                    {('--precheck-ego ' + test_ego) if test_ego else ''} \
                    --precheck-coverage {test_coverage} \
                    --ego {baseline_ego} \
                    --randomizer-seed {randomizer_seed} \
                    --seeds-folder {seeds_folder} \
                    --coverage {baseline_coverage} \
                    --seconds {trial_timeout.total_seconds()} \
                    --output-folder {test_dir}/{baseline_experiment}_{baseline_ego}_{baseline_coverage}/{test_experiment}_{test_ego}_{test_coverage}/{randomizer_seed} \
                    --process-name RQ3_{test_experiment}_{test_ego}_{test_coverage}_{randomizer_seed}
            "
    '''
    subprocess.Popen(cmd, shell=True)

