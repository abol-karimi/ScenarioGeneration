. ~/.venv/bin/activate
pip install cython
pip install numpy scipy pybind11 wheel

# Set up Carla python module
CARLA_ROOT='/home/carla'
carla_egg=carla-0.9.14-py3.7-linux-x86_64.egg
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/agents/:$PYTHONPATH
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/dist/${carla_egg}:$PYTHONPATH
export PYTHONPATH=/home/carla/ScenarioGeneration/src/:$PYTHONPATH
export PATH=/home/carla/ScenarioGeneration/src/scenariogen/scripts/:$PATH

cd /home/carla/Scenic
pip install -e .

cd /home/carla/ScenarioGeneration
pip install -r requirements.txt

pip install --upgrade numpy

/bin/bash "$@" 
