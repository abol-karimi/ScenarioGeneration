#!/bin/bash

# global variables
ScenariogenDependencies=/users/a/b/abol
CARLA_Shipping=/work/users/a/b/abol/jammy/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor
CARLA_Debug=/work/users/a/b/abol/jammy/carla/Dist/CARLA_Debug_0.9.15-169-g063cc9d90/LinuxNoEditor
CARLA_Shipping_Binary=CarlaUE4-Linux-Shipping
CARLA_Debug_Binary=CarlaUE4-Linux-Debug

# select a Carla version
CARLA_Dist=$CARLA_Debug
CARLA_Binary=$CARLA_Debug_Binary


build_images() {
    apptainer build \
        --force \
        base.sif \
        base.singularity
    
    apptainer build \
        --force \
        vulkaninfo.sif \
        vulkaninfo.singularity

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
        --bind /work/users/a/b/abol/jammy/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        --bind /work/users/a/b/abol/jammy/carla:/home/scenariogen/carla \
        --env BUILD_CARLA=T \
        --env CARLA_CONFIG=$1 \
        build.sif
}


build_ue4() {
    apptainer run \
        --nv \
        --bind /work/users/a/b/abol/jammy/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        --env BUILD_UE4=T \
        build.sif
}


run_carla() {
    export APPTAINER_CONTAINLIBS=/lib64/libvulkan.so.1,/lib64/libvulkan.so.1.3.250
    apptainer run \
        --nv \
        --bind ${CARLA_Dist}:/home/scenariogen/carla \
        --env CARLA_Binary=$CARLA_Binary \
        --env QualityLevel=Low \
        --bind /usr/share/vulkan:/usr/share/vulkan \
        --env VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/nvidia_icd.x86_64.json \
        run.sif
}


clean_ue4() {
    apptainer run \
        --nv \
        --env DEBIAN_FRONTEND=noninteractive \
        --bind /work/users/a/b/abol/jammy/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/jammy/carla/image.sif \
        bash -c \
            "export DEBIAN_FRONTEND=noninteractive && \
            cd /home/scenariogen/CarlaUnreal && \
            make ARGS='-clean'"
}


rebuild_carla() {
    apptainer run \
        --nv \
        --bind /work/users/a/b/abol/jammy/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        --bind /work/users/a/b/abol/jammy/carla:/home/scenariogen/carla \
        ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/jammy/carla/image.sif \
        bash -c \
            "export UE4_ROOT=/home/scenariogen/CarlaUnreal && \
            cd /home/scenariogen/carla && \
            make clean && \
            ./Update.sh && \
            make PythonAPI ARGS='--python-version=3.10' && \
            make package ARGS='--config=Shipping --no-zip' "
}




# parse command-line arguments
case $1 in
    build_images)
        build_images
        ;;
    run_carla)
        run_carla
        ;;
    clean_ue4)
        clean_ue4
        ;;
    build_ue4)
        build_ue4
        ;;
    build_carla)
        build_carla $2
        ;;
    rebuild_carla)
        rebuild_carla
        ;;
    *)
        echo "Usage: $0 {build_image|clean_ue4|build_ue4|build_carla|run_carla}"
        exit 1
esac

