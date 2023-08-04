. ~/.venv/bin/activate

# Set up Carla python module
CARLA_ROOT='/home/carla'
carla_egg=carla-0.9.14-py3.7-linux-x86_64.egg
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/agents/:$PYTHONPATH
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/dist/${carla_egg}:$PYTHONPATH
export PYTHONPATH=/home/carla/ScenarioGeneration/src/:$PYTHONPATH
export PYTHONPATH=/home/carla/ScenarioGeneration/:$PYTHONPATH
export PATH=/home/carla/ScenarioGeneration/:$PATH
export PATH=/home/carla/ScenarioGeneration/src/scenariogen/scripts/:$PATH
export PATH=/home/carla/ScenarioGeneration/src/scenariogen/scripts/carla:$PATH
export PATH=/home/carla/ScenarioGeneration/src/scenariogen/scripts/newtonian:$PATH
export force_color_prompt=yes

cd /home/carla/Scenic
pip install -e .

cd /home/carla/ScenarioGeneration
pip install -r requirements.txt

/bin/bash "$@"
