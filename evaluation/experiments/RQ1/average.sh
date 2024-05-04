#!/bin/bash

ScenariogenDependencies=/users/a/b/abol
CARLA_Dist=/work/users/a/b/abol/bionic/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor

module add apptainer/1.3.0-1

apptainer run \
    --cleanenv \
    --bind ${CARLA_Dist}:/home/scenariogen/carla \
    --bind ${ScenariogenDependencies}/Scenic_04-10-2024:/home/scenariogen/Scenic \
    --bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
    --bind ${ScenariogenDependencies}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
    --bind ${ScenariogenDependencies}/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
    --bind ${ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
    ${ScenariogenDependencies}/ScenarioGeneration/Apptainer/images/scenariogen.sif \
        evaluation/experiments/RQ1/average.py