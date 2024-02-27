carla_egg=carla-0.9.14-py3.7-linux-x86_64.egg \
singularity run --no-home --net --nv --nvccli \
--bind /tmp/.X11-unix:/tmp/.X11-unix:rw \
--bind $HOME/CARLA_0.9.14_RSS:/home/ak/carla \
--bind $HOME/Scenic_10-03-2023:/home/ak/Scenic \
--bind $HOME/ScenarioGeneration:/home/ak/ScenarioGeneration \
--bind $HOME/ScenarioComplexity:/home/ak/ScenarioComplexity \
--bind $HOME/carla_garage_fork:/home/ak/carla_garage_fork \
--bind $HOME/.cache:/home/ak/.cache \
Singularity/prod/scenariogen.sif "$@"