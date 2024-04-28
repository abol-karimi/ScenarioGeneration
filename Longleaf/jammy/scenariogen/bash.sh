dependencies=/users/a/b/abol

apptainer run \
--nv \
--bind $CARLA_Jammy_ROOT:/home/scenariogen/carla \
--bind $dependencies/Scenic_04-10-2024:/home/scenariogen/Scenic \
--bind $dependencies/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
--bind $dependencies/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
--bind $dependencies/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
--bind $dependencies/carla_garage_fork:/home/scenariogen/carla_garage_fork \
$dependencies/ScenarioGeneration/Longleaf/jammy/scenariogen/run.sif \
/bin/bash
