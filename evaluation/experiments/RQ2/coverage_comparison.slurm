#!/bin/bash

sbatch \
    --mail-type=FAIL \
    --mail-user=ak@cs.unc.edu \
    --job-name=RQ2_coverage_comparison \
    -o "${STORE_BASE_DIR}/ScenarioGeneration/evaluation/results/RQ2/sbatch-logs/%x_%j_%N.log" \
    --nodes=1 \
    --ntasks=1 \
    --cpus-per-task=8 \
    --mem=16G \
    -p general \
    -t 1:00:00 \
    --wrap="\
        module add apptainer/1.3.0-1; \
        ${STORE_BASE_DIR}/ScenarioGeneration/Apptainer/scripts.sh scenariogen_run bionic Shipping \
            evaluation/experiments/RQ2/coverage_comparison.py
        "