singularity shell --no-home --nv --nvccli \
--bind /tmp/.X11-unix:/tmp/.X11-unix:rw \
--bind $HOME/Scenic_10-03-2023:/home/ak/Scenic \
--bind $HOME/ScenarioGeneration:/home/ak/ScenarioGeneration \
--bind $HOME/ScenarioGeneration/Docker/dev/PythonAPI:/home/ak/PythonAPI \
--bind $HOME/ScenarioComplexity:/home/ak/ScenarioComplexity \
--bind $HOME/carla_garage_fork:/home/ak/carla_garage_fork \
Docker/dev/scenariogen.sif