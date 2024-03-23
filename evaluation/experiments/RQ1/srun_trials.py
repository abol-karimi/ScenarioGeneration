import subprocess
from itertools import product
from datetime import timedelta

generators = ['PCGF', 'Atheris', 'Random']
randomizer_seeds = [0, 1, 2, 3, 4]
trial_timeout = timedelta(hours=1)
slurm_timeout = trial_timeout + timedelta(minutes=30)
scenariogen_dependencies = '/users/a/b/abol'

for generator, randomizer_seed in product(generators, randomizer_seeds):
    cmd = f'''
        srun \
        --job-name=scenariogen \
        --cpus-per-task=12 \
        -o %N-%x-%j.out \
        --gres=gpu:1 \
        -p volta-gpu \
        --mem=16G \
        -t {str(slurm_timeout)} \
        --qos gpu_access \
        singularity run --nv \
        --env carla_egg=carla-0.9.15-py3.7-linux-x86_64.egg \
        --bind {scenariogen_dependencies}/CARLA_0.9.15:/home/scenariogen/carla \
        --bind {scenariogen_dependencies}/Scenic_10-03-2023:/home/scenariogen/Scenic \
        --bind {scenariogen_dependencies}/ScenarioGeneration:/home/scenariogen/ScenarioGeneration \
        --bind {scenariogen_dependencies}/ScenarioComplexity:/home/scenariogen/ScenarioComplexity \
        --bind {scenariogen_dependencies}/z3-4.12.6-x64-glibc-2.35:/home/scenariogen/z3 \
        --bind {scenariogen_dependencies}/carla_garage_fork:/home/scenariogen/carla_garage_fork \
        {scenariogen_dependencies}/ScenarioGeneration/Singularity/scenariogen.sif \
        evaluation/experiments/RQ1/trial.py \
        --generator {generator} \
        --ego TFPP \
        --randomizer-seed {randomizer_seed} \
        --coverage traffic-rules \
        --seconds {trial_timeout.seconds}
    '''
    subprocess.Popen(cmd, shell=True)

