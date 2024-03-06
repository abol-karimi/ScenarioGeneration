singularity run --nv \
    --bind ~/CARLA_0.9.15:/home/scenariogen/carla \
    carla.sif \
    /home/scenariogen/carla/CarlaUE4.sh -RenderOffScreen -nosound -prefernvidia