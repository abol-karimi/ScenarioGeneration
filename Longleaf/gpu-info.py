import subprocess

nodes = ['dgx01', 'dgx02', 'dgx03', 'g0301', 'g0302', 'g0303', 'g0304', 'g0305', 'g0306', 'g0307', 'g0309', 'g0310', 'g0311', 'g0312', 'g0308', 'g0313', 'g0314', 'g0315', 'g0316']

for node in nodes:
    cmd = f''' srun \
                --nodelist={node} \
                --job-name=gpu-info \
                --cpus-per-task=1 \
                --mem=1G \
                -p volta-gpu \
                --qos gpu_access \
                --gres=gpu:1 \
                -t 00:01:00 \
                -o Longleaf/gpu-info/{node}.txt \
                bash -c nvidia-smi '''

    subprocess.Popen(cmd, shell=True)
