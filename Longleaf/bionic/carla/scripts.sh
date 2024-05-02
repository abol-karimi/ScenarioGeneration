#!/bin/bash

# global variables
ScenariogenDependencies=/users/a/b/abol
CARLA_Dist_Shipping=/work/users/a/b/abol/bionic/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor
CARLA_Dist_Debug=/work/users/a/b/abol/bionic/carla/Dist/CARLA_Debug_0.9.15-169-g063cc9d90/LinuxNoEditor

# select a Carla version (Debug or Shipping)
CARLA_Dist=$CARLA_Dist_Shipping
CARLA_Binary=CarlaUE4-Linux-Shipping


build_images() {
    apptainer build \
        --force \
        build.sif \
        build.singularity
    
    apptainer build \
        --force \
        run.sif \
        run.singularity
}


build_carla() {
    apptainer run \
        --bind /work/users/a/b/abol/bionic/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        --bind /work/users/a/b/abol/bionic/carla:/home/scenariogen/carla \
        --env BUILD_CARLA=T \
        --env CARLA_CONFIG=$1 \
        build.sif
}


run_carla() {
    apptainer run \
        --nv \
        --cleanenv \
        --bind ${CARLA_Dist}:/home/scenariogen/carla \
        --env CARLA_Binary=$CARLA_Binary \
        --env QualityLevel=Epic \
        run.sif
}


sbatch_run_carla() {
  sbatch \
    --job-name="carla-bionic" \
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
                run.sif"
}


clean_ue4() {
    apptainer run \
        --env DEBIAN_FRONTEND=noninteractive \
        --bind /work/users/a/b/abol/bionic/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        base.sif \
        bash -c \
            "export DEBIAN_FRONTEND=noninteractive && \
            cd /home/scenariogen/CarlaUnreal && \
            make ARGS='-clean'"
}


rebuild_carla() {
    apptainer run \
        --nv \
        --bind /work/users/a/b/abol/bionic/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        --bind /work/users/a/b/abol/bionic/carla:/home/scenariogen/carla \
        ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/bionic/carla/image.sif \
        bash -c \
            "export UE4_ROOT=/home/scenariogen/CarlaUnreal && \
            cd /home/scenariogen/carla && \
            make clean && \
            ./Update.sh && \
            make PythonAPI ARGS='--python-version=3.8' && \
            make package ARGS='--config=Shipping --no-zip' "
}




# parse command-line arguments
case $1 in
    build_images)
        build_images
        ;;
    build_carla)
        build_carla $2
        ;;
    run_carla)
        run_carla
        ;;
    sbatch_run_carla)
        sbatch_run_carla
        ;;
    clean_ue4)
        clean_ue4
        ;;
    rebuild_carla)
        rebuild_carla
        ;;
    *)
        echo "Usage: $0 {build_image|clean_ue4|build_ue4|build_carla|run_carla}"
        exit 1
esac
