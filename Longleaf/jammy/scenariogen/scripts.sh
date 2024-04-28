#!/bin/bash

build_image() {
    # choose the image filename
    if [[ $1 == *.run ]]; then
        base=$(basename "$1")
        image=${base%.run}
    else
        image=$1
    fi

    image=${SLURM_JOB_PARTITION}_${image}
    
    apptainer build \
        --force \
        --nv \
        --build-arg driver=$1 \
        ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/jammy/carla/${image}.sif \
        ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/jammy/carla/image.singularity
}


run_carla() {
    # choose the image filename
    if [[ $1 == *.run ]]; then
        base=$(basename "$1")
        image="${base%.run}"
    else
        image=$1
    fi

    image=${SLURM_JOB_PARTITION}_${image}
    
    CARLA_Jammy_Dist=/work/users/a/b/abol/jammy/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor && \
    ScenariogenDependencies=/users/a/b/abol && \
    apptainer run \
        --nv \
        --bind ${CARLA_Jammy_Dist}:/home/scenariogen/carla \
        ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/jammy/carla/${image}.sif \
        bash -c \
            "vulkaninfo && \
            /home/scenariogen/carla/CarlaUE4/Binaries/Linux/CarlaUE4-Linux-Shipping \
            CarlaUE4 \
            -nosound \
            -RenderOffScreen \
            -quality-level=Low \
            -prefernvidia \
            -carla-rpc-port=0 \
            -carla-streaming-port=0 \
            -carla-secondary-port=0"    
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


build_ue4() {
    apptainer run \
        --nv \
        --bind /work/users/a/b/abol/jammy/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/jammy/carla/image.sif \
        bash -c \
            "cd /home/scenariogen/CarlaUnreal && \
            ./Setup.sh -noask && \
            ./GenerateProjectFiles.sh && \
            make "
}

build_carla() {
    apptainer run \
        --nv \
        --bind /work/users/a/b/abol/jammy/CarlaUnreal:/home/scenariogen/CarlaUnreal \
        --bind /work/users/a/b/abol/jammy/carla:/home/scenariogen/carla \
        ${ScenariogenDependencies}/ScenarioGeneration/Longleaf/jammy/carla/image.sif \
        bash -c \
            "export UE4_ROOT=/home/scenariogen/CarlaUnreal && \
            cd /home/scenariogen/carla && \
            make PythonAPI ARGS='--python-version=3.10' && \
            make package ARGS='--config=Shipping --no-zip' "
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
    build_image)
        # https://download.nvidia.com/XFree86/Linux-x86_64/
        # https://packages.ubuntu.com/jammy/allpackages?format=txt.gz
        build_image $2
        ;;
    run_carla)
        run_carla $2
        ;;
    clean_ue4)
        clean_ue4
        ;;
    build_ue4)
        build_ue4
        ;;
    build_carla)
        build_carla
        ;;
    rebuild_carla)
        rebuild_carla
        ;;
    *)
        echo "Usage: $0 {build_image|clean_ue4|build_ue4|build_carla|run_carla}"
        exit 1
esac

