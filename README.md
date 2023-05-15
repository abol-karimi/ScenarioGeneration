# ScenarioGeneration

To run the Docker container:
`sudo docker run --rm -it --privileged --gpus all --net=host -e DISPLAY=$DISPLAY -e SDL_VIDEODRIVER=x11 -v /tmp/.X11-unix:/tmp/.X11-unix:rw   --mount type=bind,source=/home/ak/ScenarioGeneration,target=/home/carla/ScenarioGeneration --mount type=bind,source=/home/ak/Scenic-latest,target=/home/carla/Scenic scenic:latest`

Run `./new.py -h` for making a new scenario
Run `./replay.py -h` to play an existing scenario
Run `./autopilot.py -h` to play an existing scenario with Carla's autopilot driving the ego vehicle
