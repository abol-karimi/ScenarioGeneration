singularity run --net --network=bridge --dns 8.8.8.8 --nv \
--env carla_egg=carla-0.9.14-py3.7-linux-x86_64.egg \
--bind $HOME/CARLA_0.9.14_RSS:/home/scenariogen/carla \
--bind /tmp/.X11-unix:/tmp/.X11-unix:rw \
--bind $HOME/Scenic_10-03-2023:/home/scenariogen/Scenic \
--bind $HOME/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
--bind $HOME/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
--bind $HOME/carla_garage_fork:/home/scenariogen/carla_garage_fork \
Singularity/prod/scenariogen.sif "$@"