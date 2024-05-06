#!/bin/bash

# Longleaf
Loneleaf_CarlaUnreal=${WORK_BASE_DIR}/bionic/CarlaUnreal
Longleaf_CARLA_Dist_Shipping=${WORK_BASE_DIR}/bionic/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor
Longleaf_CARLA_Dist_Debug=${WORK_BASE_DIR}/bionic/carla/Dist/CARLA_Debug_0.9.15-169-g063cc9d90/LinuxNoEditor
Longleaf_CARLA_egg=carla-0.9.15-py3.8-linux-x86_64.egg
Longleaf_Scenariogen_Dependencies=${STORE_BASE_DIR}
Longleaf_SCENIC_Version=Scenic_04-10-2024

# Local
Local_CarlaUnreal=/media/ak/Files/CarlaUnreal
Local_CARLA_SRC=/media/ak/Files/carla
Local_CARLA_Dist_Shipping=/media/ak/Files/CARLA_0.9.15
Local_CARLA_egg=carla-0.9.15-py3.7-linux-x86_64.egg
Local_Scenariogen_Dependencies=/home/ak
Local_SCENIC_Version=Scenic_05-03-2024

# select a version
CarlaUnreal=${Local_CarlaUnreal}
CARLA_SRC=${Local_CARLA_SRC}
CARLA_Dist=${Local_CARLA_Dist_Shipping}
CARLA_Binary=CarlaUE4-Linux-Shipping
CARLA_egg=${Local_CARLA_egg}
Scenariogen_Dependencies=${Local_Scenariogen_Dependencies}
SCENIC_Version=${Local_SCENIC_Version}

build_image() {
    apptainer build \
        --force \
        --warn-unused-build-args \
        --build-arg CARLA_egg=${CARLA_egg} \
        --build-arg Scenariogen_Dependencies=${Scenariogen_Dependencies} \
        --build-arg SCENIC_Version=${SCENIC_Version} \
        images/$1.sif \
        definitions/$1.apptainer
}

build_shell() {
    apptainer shell \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        images/carla-build-$1.sif
}

clean_ue4() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --env CLEAN_UE4=T \
        images/carla-build-$1.sif
}

build_ue4() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --env BUILD_UE4=T \
        images/carla-build-$1.sif
}

clean_carla() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        --env CLEAN_CARLA=T \
        images/carla-build-$1.sif
}

update_carla() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        --env UPDATE_CARLA=T \
        images/carla-build-$1.sif
}

build_carla() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        --env BUILD_CARLA=T \
        --env CARLA_BUILD_CONFIG=$2 \
        images/carla-build-$1.sif
}

build_rss() {
    apptainer run \
        --bind ${CarlaUnreal}:/home/scenariogen/CarlaUnreal \
        --bind ${CARLA_SRC}:/home/scenariogen/carla \
        --env BUILD_RSS=T \
        --env CARLA_BUILD_CONFIG=$2 \
        images/carla-build-$1.sif
}

run_carla() {
    apptainer run \
        --nv \
        --cleanenv \
        --bind ${CARLA_Dist}:/home/scenariogen/carla \
        --env CARLA_Binary=$CARLA_Binary \
        --env QualityLevel=Epic \
        images/carla-run-$1.sif
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
                --bind ${CARLA_Dist}:/home/scenariogen/carla \
                --env CARLA_Binary=$CARLA_Binary \
                --env QualityLevel=Epic \
                images/carla-run-$1.sif"
}

SUT() {
    apptainer run \
        --nv \
        --bind ${CARLA_Dist}:/home/scenariogen/carla \
        --env CARLA_egg=${CARLA_egg} \
        --bind ${Scenariogen_Dependencies}/${SCENIC_Version}:/home/scenariogen/Scenic \
        --bind ${Scenariogen_Dependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
        --bind ${Scenariogen_Dependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
        images/scenariogen-$1.sif \
            SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
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
                --bind ${CARLA_Dist}:/home/scenariogen/carla \
                --bind ${ScenariogenDependencies}/${SCENIC_Version}:/home/scenariogen/Scenic \
                --bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
                --bind ${ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
                images/scenariogen-$1.sif \
                    SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
                        --ego-module evaluation.agents.TFPP \
                        --coverage-module traffic-rules
            "
}


# parse command-line arguments
"$@"
