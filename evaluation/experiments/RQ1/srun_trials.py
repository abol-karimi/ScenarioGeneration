import subprocess
from itertools import product
from datetime import timedelta

generators = ['Atheris']
randomizer_seeds = [0, 1, 2, 3, 4]
trials = product(generators, randomizer_seeds)
# trials = (
    # ('PCGF', 0),
    # ('PCGF', 2),
    # ('PCGF', 4),
    # ('Random', 0),
    # ('Random', 1),
#   )
trial_timeout = timedelta(hours=12)
slurm_timeout = trial_timeout + timedelta(minutes=30)
ScenariogenDependencies = '/users/a/b/abol'
CARLA_Dist = '/work/users/a/b/abol/bionic/carla/Dist/CARLA_Shipping_0.9.15-169-g063cc9d90/LinuxNoEditor'

for generator, randomizer_seed in trials:
    cmd = f'''
        sbatch \
        --job-name={generator}_{randomizer_seed} \
        -o "%x-%j-%N.log" \
        --nodes=1 \
        --ntasks=1 \
        --cpus-per-task=8 \
        --mem=20G \
        --qos gpu_access \
        -p volta-gpu \
        --gres=gpu:tesla_v100-sxm2-16gb:1 \
        -t {str(slurm_timeout)} \
        --wrap="\
            module add apptainer/1.3.0-1; \
            apptainer run \
                --net \
                --network=none \
                --nv \
                --cleanenv \
                --bind {CARLA_Dist}:/home/scenariogen/carla \
                --bind {ScenariogenDependencies}/Scenic_04-10-2024:/home/scenariogen/Scenic \
                --bind {ScenariogenDependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
                --bind {ScenariogenDependencies}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
                --bind {ScenariogenDependencies}/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
                --bind {ScenariogenDependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
                {ScenariogenDependencies}/ScenarioGeneration/Longleaf/bionic/scenariogen/scenariogen.sif \
                    evaluation/experiments/RQ1/trial.py \
                        --generator {generator} \
                        --ego TFPP \
                        --randomizer-seed {randomizer_seed} \
                        --coverage traffic-rules \
                        --seconds {trial_timeout.seconds}
            "
    '''
    subprocess.Popen(cmd, shell=True)

