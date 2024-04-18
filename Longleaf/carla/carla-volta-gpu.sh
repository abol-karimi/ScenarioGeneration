volta_nodes=($(sinfo -p volta-gpu -N -h -o "%N"))

for node in ${volta_nodes[@]}; do
  sbatch \
    --job-name=drivers \
    -o "%j-%N-%x.txt" \
    -p volta-gpu \
    --nodes=1 \
    --ntasks=1 \
    --cpus-per-task=16 \
    --qos gpu_access \
    --gres=gpu:1 \
    --mem=16G \
    -t 1:00:00 \
    --wrap="srun singularity run \
                    --bind /users/a/b/abol/carla/Dist/CARLA_Debug_0.9.15-168-g20a4a4618/LinuxNoEditor:/home/scenariogen/carla \
                    /users/a/b/abol/ScenarioGeneration/Longleaf/carla/carla-run.sif "
done

singularity run --bind /users/a/b/abol/carla/Dist/CARLA_Debug_0.9.15-168-g20a4a4618/LinuxNoEditor:/home/scenariogen/carla /users/a/b/abol/ScenarioGeneration/Longleaf/carla/carla-run.sif