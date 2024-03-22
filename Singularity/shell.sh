nvidia-smi

singularity shell --nv \
--env carla_egg=carla-0.9.15-py3.7-linux-x86_64.egg \
--bind $ScenariogenDependencies/CARLA_0.9.15:/home/scenariogen/carla \
--bind $ScenariogenDependencies/Scenic_10-03-2023:/home/scenariogen/Scenic \
--bind $ScenariogenDependencies/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
--bind $ScenariogenDependencies/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
--bind $ScenariogenDependencies/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
--bind $ScenariogenDependencies/carla_garage_fork:/home/scenariogen/carla_garage_fork \
$ScenariogenDependencies/ScenarioGeneration/Singularity/scenariogen.sif
