#!/bin/bash

./scripts.sh scenariogen_run bionic Shipping \
    SUT.py evaluation/seeds/random/seeds/4a27e66ba63fd3d4ce8f2d2ab76282ffeb3aafa6 \
        --simulator carla \
        --ego-module evaluation.agents.TFPP \
        --coverage-module traffic-rules \
        --render-spectator

# 1d6da581c30402e94a8c94b1ef2b40a1cde442f2
# 2a831beb5b9f48baf42f0801df9bdeee15d61b17
# 2e8850f0dd73f16eff512788d1c0dcc628583bb4
# 4a27e66ba63fd3d4ce8f2d2ab76282ffeb3aafa6
