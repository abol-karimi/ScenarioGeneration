#!/bin/bash

sbatch \
    --mail-type=FAIL \
    --mail-user=ak@cs.unc.edu \
    --job-name=RQ1_aggregate \
    -o "${STORE_BASE_DIR}/ScenarioGeneration/evaluation/results/RQ1/sbatch-logs/%x_%j_%N.log" \
    --nodes=1 \
    --ntasks=1 \
    --cpus-per-task=32 \
    --mem=256G \
    -p general \
    -t 3:00:00 \
    --wrap="\
        module add apptainer/1.3.0-1; \
        ${STORE_BASE_DIR}/ScenarioGeneration/Apptainer/scripts.sh scenariogen_run bionic Shipping \
            evaluation/experiments/RQ1/aggregate.py
        "