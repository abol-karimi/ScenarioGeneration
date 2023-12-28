sudo docker run --rm -it --privileged \
--gpus all \
--net=host \
-e DISPLAY=$DISPLAY \
-e SDL_VIDEODRIVER=x11 \
-v /tmp/.X11-unix:/tmp/.X11-unix:rw \
--mount type=bind,source=$HOME/Scenic_10-03-2023,target=/home/carla/Scenic \
--mount type=bind,source=$HOME/ScenarioGeneration,target=/home/carla/ScenarioGeneration \
--mount type=bind,source=$HOME/ScenarioGeneration/Docker/dev/PythonAPI,target=/home/carla/PythonAPI \
--mount type=bind,source=$HOME/ScenarioComplexity,target=/home/carla/ScenarioComplexity \
--mount type=bind,source=$HOME/carla_garage_fork,target=/home/carla/carla_garage_fork \
scenariogen:dev
