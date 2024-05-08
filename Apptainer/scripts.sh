#!/bin/bash

# choice of base image for the containers (bionic, focal, jammy)
if [[ $# -gt 2 ]]; then
    BASE_IMAGE_DIST=$3
else
    BASE_IMAGE_DIST=bionic
fi

# choice of build config for CARLA (Debug, Shipping)
if [[ $# -gt 3 ]]; then
    CARLA_BUILD_CONFIG=$4
else
    CARLA_BUILD_CONFIG=Shipping
fi


# choice of CARLA (comment out the one you don't want to use)
CARLA_BUILD_NUMBER=0.9.15-169-g063cc9d90 # Longleaf
CARLA_BUILD_NUMBER=0.9.15-187-g7a540559a # Local
CARLA_EGG=carla-0.9.15-py3.8-linux-x86_64.egg

# choice of SCENIC (comment out the one you don't want to use)
SCENIC_VERSION=Scenic_04-10-2024 # Longleaf
SCENIC_VERSION=Scenic_05-03-2024 # Local


# template variables
CarlaUnreal=${WORK_BASE_DIR}/${BASE_IMAGE_DIST}/CarlaUnreal
CARLA_SRC=${WORK_BASE_DIR}/${BASE_IMAGE_DIST}/carla
CARLA_DIST=${WORK_BASE_DIR}/${BASE_IMAGE_DIST}/carla/Dist/CARLA_${CARLA_BUILD_CONFIG}_${CARLA_BUILD_NUMBER}/LinuxNoEditor
CARLA_BINARY=CarlaUE4-Linux-${CARLA_BUILD_CONFIG}
SCENARIOGEN_DEPENDENCIES=${STORE_BASE_DIR}


build_image() {
    apptainer build \
        --force \
        --warn-unused-build-args \
        --build-arg CARLA_EGG=${CARLA_EGG} \
        --build-arg SCENARIOGEN_DEPENDENCIES=${SCENARIOGEN_DEPENDENCIES} \
        --build-arg SCENIC_VERSION=${SCENIC_VERSION} \
        images/$1-${BASE_IMAGE_DIST}.sif \
        definitions/$1-${BASE_IMAGE_DIST}.apptainer
}

build_shell() {
    apptainer shell \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        images/carla-build-${BASE_IMAGE_DIST}.sif
}

clean_ue4() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --env CLEAN_UE4=T \
        images/carla-build-${BASE_IMAGE_DIST}.sif
}

build_ue4() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --env BUILD_UE4=T \
        images/carla-build-${BASE_IMAGE_DIST}.sif
}

clean_carla() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        --env CLEAN_CARLA=T \
        images/carla-build-${BASE_IMAGE_DIST}.sif
}

update_carla() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        --env UPDATE_CARLA=T \
        images/carla-build-${BASE_IMAGE_DIST}.sif
}

build_carla() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        --env BUILD_CARLA=T \
        --env CARLA_BUILD_CONFIG=${CARLA_BUILD_CONFIG} \
        images/carla-build-${BASE_IMAGE_DIST}.sif
}

build_rss() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        --env BUILD_RSS=T \
        --env CARLA_BUILD_CONFIG=${CARLA_BUILD_CONFIG} \
        images/carla-build-${BASE_IMAGE_DIST}.sif
}

run_carla() {
    apptainer run \
        --nv \
        --cleanenv \
        --bind ${CARLA_DIST}:/home/scenariogen/carla \
        --env CARLA_BINARY=$CARLA_BINARY \
        --env QUALITY_LEVEL=Epic \
        images/carla-run-${BASE_IMAGE_DIST}.sif
}

sbatch_run_carla() {
  sbatch \
    --job-name="carla-run" \
    -o "%x-%j-%N.log" \
    --nodes=1 \
    --ntasks=1 \
    --cpus-per-task=4 \
    --mem=5G \
    --qos gpu_access \
    -p volta-gpu \
    --gres=gpu:tesla_v100-sxm2-16gb:1 \
    -t 01:00:00 \
    --wrap="module add apptainer/1.3.0-1; \
            apptainer run \
                --nv \
                --cleanenv \
                --bind ${CARLA_DIST}:/home/scenariogen/carla \
                --env CARLA_BINARY=$CARLA_BINARY \
                --env QUALITY_LEVEL=Epic \
                images/carla-run-${BASE_IMAGE_DIST}.sif"
}

scenariogen_shell() {
    apptainer shell \
        --nv \
        --bind ${CARLA_DIST}:/home/scenariogen/carla \
        --bind ${SCENARIOGEN_DEPENDENCIES}/${SCENIC_VERSION}:/home/scenariogen/Scenic \
        --bind ${SCENARIOGEN_DEPENDENCIES}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
        --bind ${SCENARIOGEN_DEPENDENCIES}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
        images/scenariogen-${BASE_IMAGE_DIST}.sif
}

SUT() {
    apptainer run \
        --nv \
        --bind ${CARLA_DIST}:/home/scenariogen/carla \
        --bind ${SCENARIOGEN_DEPENDENCIES}/${SCENIC_VERSION}:/home/scenariogen/Scenic \
        --bind ${SCENARIOGEN_DEPENDENCIES}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
        --bind ${SCENARIOGEN_DEPENDENCIES}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
        images/scenariogen-${BASE_IMAGE_DIST}.sif \
            SUT.py evaluation/seeds/random/seeds/231d7d343f2b9d6c269f57cbfb439fa4e721aed3 \
                --ego-module evaluation.agents.BehaviorAgent \
                --coverage-module traffic-rules \
                --render-spectator
}

sbatch_SUT() {
  sbatch \
    --job-name="SUT" \
    -o "%x-%j-%N.log" \
    --nodes=1 \
    --ntasks=1 \
    --cpus-per-task=8 \
    --mem=10G \
    --qos gpu_access \
    -p volta-gpu \
    --gres=gpu:tesla_v100-sxm2-16gb:1 \
    -t 01:00:00 \
    --wrap="module add apptainer/1.3.0-1; \
            apptainer run \
                --nv \
                --cleanenv \
                --bind ${CARLA_DIST}:/home/scenariogen/carla \
                --bind ${ScenariogenDependencies}/${SCENIC_VERSION}:/home/scenariogen/Scenic \
                --bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
                --bind ${ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
                images/scenariogen-${BASE_IMAGE_DIST}.sif \
                    SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
                        --ego-module evaluation.agents.TFPP \
                        --coverage-module traffic-rules
            "
}


# parse command-line arguments
"$@"