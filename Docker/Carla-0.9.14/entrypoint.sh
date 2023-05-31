. ~/.venv/bin/activate
pip install cython
pip install numpy scipy pybind11 wheel

# Set up Carla python module
CARLA_ROOT='/home/carla'
carla_egg=carla-0.9.14-py3.7-linux-x86_64.egg
PYTHONPATH="${CARLA_ROOT}/PythonAPI/carla/:${CARLA_ROOT}/PythonAPI/carla/agents/:${CARLA_ROOT}/PythonAPI/carla/dist/${carla_egg}"
export PYTHONPATH=${PYTHONPATH}
echo "export PYTHONPATH=${PYTHONPATH}" >> .bashrc

cd /home/carla/Scenic
pip install -e .

cd /home/carla/ScenarioGeneration
pip install -r requirements.txt

/bin/bash "$@" 
