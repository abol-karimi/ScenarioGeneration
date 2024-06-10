#!/usr/bin/env python3

import subprocess
from itertools import product, permutations
from datetime import timedelta
import os

generators = ('PCGF', )
egos = ('autopilot', 'BehaviorAgent', 'intersectionAgent', 'TFPP')
randomizer_seeds = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, )
randomizer_seeds = (3, )
coverages = ('traffic-rules', )
trial_timeout = timedelta(hours=24)
timeout_buffer = timedelta(minutes=30)

# dependent variables
slurm_timeout = trial_timeout + timeout_buffer

# For RQ2, we only vary the ego 
#  from the test-case-generation to test-case-execution trials.
ego_pairs = tuple(permutations(egos, r=2))
ego_pairs = (('intersectionAgent', 'TFPP'), )
trials = tuple(product(generators, ego_pairs, randomizer_seeds, coverages))
dd = slurm_timeout.days
hh = slurm_timeout.seconds//3600
mm = (slurm_timeout.seconds%3600)//60
ss = slurm_timeout.seconds%60
STORE_BASE_DIR = os.environ.get('STORE_BASE_DIR')

for generator, (gen_ego, test_ego), randomizer_seed, coverage in trials:
    if gen_ego in {'BehaviorAgent', 'TFPP'}:
        continue
    cmd = f'''
        sbatch \
        --mail-type=FAIL \
        --mail-user=ak@cs.unc.edu \
        --job-name=RQ2_{generator}_{gen_ego}_{test_ego}_{coverage}_{randomizer_seed} \
        -o "{STORE_BASE_DIR}/ScenarioGeneration/evaluation/results/RQ2/sbatch-logs/%x_%j_%N.log" \
        --nodes=1 \
        --ntasks=1 \
        --cpus-per-task=8 \
        --mem={20 if test_ego == 'intersectionAgent' else 30}G \
        {'-p general' if test_ego == 'intersectionAgent' else '--qos gpu_access -p volta-gpu --gres=gpu:1'} \
        -t {dd}-{hh}:{mm}:{ss} \
        --wrap="\
            module add apptainer/1.3.0-1; \
            {STORE_BASE_DIR}/ScenarioGeneration/Apptainer/scripts.sh scenariogen_run bionic Shipping \
                evaluation/experiments/RQ2/trial.py \
                    --ego {test_ego} \
                    --seeds-folder evaluation/results/RQ1/{generator}_{gen_ego}_{coverage}/{randomizer_seed}/fuzz-inputs \
                    --coverage {coverage} \
                    --seconds {trial_timeout.total_seconds()} \
                    --output-folder evaluation/results/RQ2/{generator}_{gen_ego}_{coverage}/{test_ego}/{randomizer_seed}
            "
    '''
    subprocess.Popen(cmd, shell=True)

