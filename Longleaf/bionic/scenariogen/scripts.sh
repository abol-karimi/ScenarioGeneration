#!/bin/bash

# global variables
ScenariogenDependencies=/users/a/b/abol
CARLA_Dist_Shipping=/work/users/a/b/abol/bionic/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor
CARLA_Dist_Debug=/work/users/a/b/abol/bionic/carla/Dist/CARLA_Debug_0.9.15-169-g063cc9d90/LinuxNoEditor

# select a Carla version (Debug or Shipping)
CARLA_Dist=$CARLA_Dist_Shipping


build_images() {
    apptainer build \
        --force \
        --build-arg ScenariogenDependencies=$ScenariogenDependencies \
        scenariogen.sif \
        scenariogen.singularity
   
}


SUT() {
    apptainer run \
        --nv \
        --cleanenv \
        --bind ${CARLA_Dist}:/home/scenariogen/carla \
        --bind ${ScenariogenDependencies}/Scenic_04-10-2024:/home/scenariogen/Scenic \
        --bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
        --bind ${ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
        scenariogen.sif \
            cd /home/scenariogen/ScenarioGeneration; \
            SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
                --ego-module evaluation.agents.TFPP \
                --coverage-module traffic-rules
}


sbatch_SUT() {
  sbatch \
    --job-name="SUT-bionic" \
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
                --bind ${ScenariogenDependencies}/Scenic_04-10-2024:/home/scenariogen/Scenic \
                --bind ${ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
                --bind ${ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
                scenariogen.sif \
                    SUT.py evaluation/seeds/random/seeds/1d6da581c30402e94a8c94b1ef2b40a1cde442f2 \
                        --ego-module evaluation.agents.TFPP \
                        --coverage-module traffic-rules
            "
}


# parse command-line arguments
case $1 in
    build_images)
        build_images
        ;;
    SUT)
        SUT
        ;;
    sbatch_SUT)
        sbatch_SUT
        ;;
    *)
        echo "Usage: $0 {build_images|SUT|sbatch_SUT}"
        exit 1
esac
