import subprocess
from itertools import product
from datetime import timedelta

generators = ['PCGF', 'Atheris', 'Random']
randomizer_seeds = [0, 1, 2, 3, 4]
timeout = timedelta(minutes=5)

for generator, randomizer_seed in product(generators, randomizer_seeds):
    cmd = [
        "ScenariogenDependencies=/users/a/b/abol",
        "srun",
        "--job-name=scenariogen",
        "--cpus-per-task=12",
        "-o %N-%x-%j.out",
        "--gres=gpu:1",
        "-p volta-gpu",
        "--mem=16G",
        f"-t {timeout}",
        "--qos gpu_access",
        "evaluation/experiments/RQ1/trial.py",
        f"--generator {generator}",
        "--ego evaluation.agents.TFPP",
        f"--randomizer-seed {randomizer_seed}",
        "--coverage traffic-rules",
        f"--seconds {timeout.total_seconds()}",
    ]

    subprocess.run(cmd)

