nvidia-smi

singularity run --net --network=none --nv \
--env carla_egg=carla-0.9.14-py3.7-linux-x86_64.egg \
--bind /users/a/b/abol/CARLA_0.9.14_RSS:/home/scenariogen/carla \
--bind /users/a/b/abol/Scenic_10-03-2023:/home/scenariogen/Scenic \
--bind /users/a/b/abol/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
--bind /users/a/b/abol/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
--bind /users/a/b/abol/carla_garage_fork:/home/scenariogen/carla_garage_fork \
Singularity/prod/scenariogen.sif "$@"

# singularity run --no-home --nv --nvccli \
# --env DISPLAY=$DISPLAY,SDL_VIDEODRIVER=x11 \
# --bind /tmp/.X11-unix:/tmp/.X11-unix:rw \
# scenariogen-dev.sif -RenderOffScreen -ini:[/Script/Engine.RendererSettings]:r.GraphicsAdapter=2