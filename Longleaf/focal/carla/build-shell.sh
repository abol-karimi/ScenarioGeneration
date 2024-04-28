#!/bin/bash
apptainer shell \
    --nv \
    --bind /users/a/b/abol/CarlaUnreal:/home/scenariogen/CarlaUnreal \
    --env UE4_ROOT=/home/scenariogen/CarlaUnreal \
    --bind /users/a/b/abol/carla:/home/scenariogen/carla \
    build.sif
