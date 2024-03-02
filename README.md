# ScenarioGeneration

To download the docker image, run: `docker pull abelkarimi/scenariogen`

To run the Docker container:
`sudo docker run --rm -it --privileged --gpus all --net=host -e DISPLAY=$DISPLAY -e SDL_VIDEODRIVER=x11 -v /tmp/.X11-unix:/tmp/.X11-unix:rw`

Run `~/CarlaUE4.sh & disown` to run the Carla simulator, before running scripts that need Carla.

Run any script from `~/ScenarioGeneration` (i.e. the project root folder).
* For running the experiment scripts in `experiments/` prefix them with the full relative path e.g. `experiments/predicate-coverage/experiment.py`. These scripts don't take CLI options, as all the parameters are set in the scripts.
* For running the scripts in `src/scenariogen/scripts` just type the script name, as the folder is in `$PATH`. Run the scripts with the `-h` flag to see the options.


## carla_garage_fork
After installing the pip requirements, run:
`get_pretrained_models.sh`
