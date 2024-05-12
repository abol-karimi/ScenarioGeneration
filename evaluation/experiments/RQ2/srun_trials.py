#!/usr/bin/env python3

import subprocess
from itertools import product, permutations
from datetime import timedelta
import os

generators = ('Atheris', 'PCGF', 'Random', )
egos = ('autopilot', 'BehaviorAgent', 'TFPP')
randomizer_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, )
coverages = ('traffic-rules', )
trial_timeout = timedelta(hours=24)
timeout_buffer = timedelta(minutes=30)

# dependent variables
slurm_timeout = trial_timeout + timeout_buffer

# For RQ2, we only vary the ego 
#  between the test-case-generation trials and
#  and the test-case-execution trials.
trials = product(generators, permutations(egos, r=2), randomizer_seeds, coverages)
dd = slurm_timeout.days
hh = slurm_timeout.seconds//3600
mm = (slurm_timeout.seconds%3600)//60
ss = slurm_timeout.seconds%60
STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')

for generator, (gen_ego, test_ego), randomizer_seed, coverage in trials:
    cmd = f'''
        sbatch \
        --mail-type=FAIL \
        --mail-user=ak@cs.unc.edu \
        --job-name=RQ2_{generator}_{gen_ego}_{coverage}_{randomizer_seed}_{test_ego} \
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
                evaluation/experiments/RQ2/trial.py \
                    --ego {test_ego} \
                    --seeds-folder evaluation/results/RQ1/{generator}_{gen_ego}_{coverage}/{randomizer_seed}/fuzz-inputs \
                    --coverage {coverage} \
                    --seconds {trial_timeout.total_seconds()} \
                    --output-folder evaluation/results/RQ2/{generator}_{gen_ego}_{coverage}/{randomizer_seed}/{test_ego}
            "
    '''
    subprocess.Popen(cmd, shell=True)

