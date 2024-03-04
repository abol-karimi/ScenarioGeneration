nvidia-smi

singularity run --net --network=none --nv \
--bind /tmp/.X11-unix:/tmp/.X11-unix:rw \
--env carla_egg=carla-0.9.15-py3.7-linux-x86_64.egg \
--bind $DependencyFolder/CARLA_0.9.15:/home/scenariogen/carla \
--bind $DependencyFolder/Scenic_10-03-2023:/home/scenariogen/Scenic \
--bind $DependencyFolder/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
--bind $DependencyFolder/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
--bind $DependencyFolder/carla_garage_fork:/home/scenariogen/carla_garage_fork \
"$@"
