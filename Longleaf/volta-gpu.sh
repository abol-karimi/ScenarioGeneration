volta_nodes=($(sinfo -p volta-gpu -N -h -o "%N"))

for node in ${volta_nodes[@]}; do
    sbatch \
    --job-name=carla-$node \
    --nodelist=$node \
    run.slurm
done

