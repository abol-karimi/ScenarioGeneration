#!/bin/bash

# global variables
ScenariogenDependencies=/users/a/b/abol
CARLA_Shipping=/work/users/a/b/abol/focal/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor
CARLA_Debug=/work/users/a/b/abol/focal/carla/Dist/CARLA_Debug_0.9.15-169-g063cc9d90/LinuxNoEditor

CARLA_Shipping_Binary=CarlaUE4-Linux-Shipping
CARLA_Debug_Binary=CarlaUE4-Linux-Debug

# select a Carla version
CARLA_Dist=$CARLA_Debug
CARLA_Binary=$CARLA_Debug_Binary


build_images() {
        # --bind $ScenariogenDependencies/ScenarioGeneration/Longleaf/focal/Vulkan-Loader:/home/scenariogen/Vulkan-Loader \
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
        --bind /work/users/a/b/abol/focal/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        --bind /work/users/a/b/abol/focal/carla:/home/scenariogen/carla \
        --env BUILD_CARLA=T \
        --env CARLA_CONFIG=$1 \
        build.sif
}


run_carla() {
    
    # Instead of binding the node's vulkan loader
        # --bind /lib64/libvulkan.so.1.3.250:/.singularity.d/libs/libvulkan.so.1 \
    # we'll build the loader from source.

    export APPTAINER_CONTAINLIBS=/lib64/libvulkan.so.1
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
        --env DEBIAN_FRONTEND=noninteractive \
        --bind /work/users/a/b/abol/focal/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        base.sif \
        bash -c \
            "export DEBIAN_FRONTEND=noninteractive && \
            cd /home/scenariogen/CarlaUnreal && \
            make ARGS='-clean'"
}


rebuild_carla() {
    apptainer run \
        --nv \
        --bind /work/users/a/b/abol/focal/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        --bind /work/users/a/b/abol/focal/carla:/home/scenariogen/carla \
        ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/focal/carla/image.sif \
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
