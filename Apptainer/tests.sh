#!/bin/bash

./scripts.sh scenariogen_run bionic Shipping \
    SUT.py evaluation/seeds/random/seeds/231d7d343f2b9d6c269f57cbfb439fa4e721aed3 \
                    --ego-module evaluation.agents.BehaviorAgent \
                    --coverage-module traffic-rules \
                    --render-spectator