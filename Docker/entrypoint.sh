. ~/.venv/bin/activate
pip install cython
pip install numpy scipy pybind11 wheel

cd /home/carla/Scenic
pip install -e .

cd /home/carla/ScenarioGeneration
pip install -r requirements.txt

/bin/bash "$@"
