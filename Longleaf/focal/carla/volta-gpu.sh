volta_nodes=($(sinfo -p volta-gpu -N -h -o "%N"))

if [ $# -ge 1 ]; then
    echo "Setting ScenariogenDependencies to $1"
    ScenariogenDependencies=$1
elif [ -z $ScenariogenDependencies ]; then
    echo "ScenariogenDependencies is neither passed as an argument nor as an environment variable! Terminating the script..."
else
    for node in ${volta_nodes[@]}; do
        sbatch \
        --job-name=SUT-$node \
        --nodelist=$node \
        $ScenariogenDependencies/ScenarioGeneration/Longleaf/carla/run.slurm
    done
fi
