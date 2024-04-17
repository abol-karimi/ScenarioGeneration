volta_nodes=(dgx01 dgx02 dgx03 g0301 g0302 g0303 g0304 g0305 g0306 g0307 g0308 g0309 g0310 g0311 g0312 g0313 g0314 g0315 g0316)
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
                    --bind $1/carla/Dist/CARLA_Debug_0.9.15-166-gf22d49d78/LinuxNoEditor:/home/scenariogen/carla \
                    $1/ScenarioGeneration/Longleaf/Carla/drivers.sif "
done

