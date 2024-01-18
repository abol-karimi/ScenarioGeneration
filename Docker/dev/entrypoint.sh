#--------------------------------------------
#---------- install python modules ----------
#--------------------------------------------
. ~/.venv/bin/activate
pip install -e /home/carla/Scenic
pip install -r /home/carla/ScenarioGeneration/requirements.txt
pip install -r /home/carla/ScenarioComplexity/requirements.txt

# TF++ AV agent
WORK_DIR=/home/carla/carla_garage_fork
pip install -r ${WORK_DIR}/scenario_runner/requirements.txt
pip install -r ${WORK_DIR}/leaderboard/requirements.txt
pip install -r ${WORK_DIR}/team_code/requirements.txt


#--------------------------------------------------
#---------- Prepare bash's initial state ----------
#--------------------------------------------------

# Carla
export CARLA_ROOT='/home/carla'
carla_egg=carla-0.9.14-py3.7-linux-x86_64.egg
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/agents/:$PYTHONPATH
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/dist/${carla_egg}:$PYTHONPATH

# ScenarioGeneneration
export PYTHONPATH=/home/carla/ScenarioGeneration/src/:$PYTHONPATH
export PYTHONPATH=/home/carla/ScenarioGeneration/:$PYTHONPATH
export PATH=/home/carla/ScenarioGeneration/:$PATH
export PATH=/home/carla/ScenarioGeneration/tests/:$PATH
export PATH=/home/carla/ScenarioGeneration/src/scenariogen/scripts/:$PATH
export PATH=/home/carla/ScenarioGeneration/src/scenariogen/scripts/carla:$PATH
export PATH=/home/carla/ScenarioGeneration/src/scenariogen/scripts/newtonian:$PATH
export PATH=/home/carla/z3-4.8.10-x64-ubuntu-18.04/bin:$PATH

# ScenarioComplexity
export PYTHONPATH=/home/carla/ScenarioComplexity/src/:$PYTHONPATH
export PYTHONPATH=/home/carla/ScenarioComplexity/:$PYTHONPATH
export PATH=$PATH:/home/carla/ScenarioComplexity/src/complexgen/scripts/

# TF++ AV agent
export SCENARIO_RUNNER_ROOT=${WORK_DIR}/scenario_runner
export LEADERBOARD_ROOT=${WORK_DIR}/leaderboard
export WORK_DIR=${WORK_DIR}
export PYTHONPATH=${WORK_DIR}:${WORK_DIR}/team_code:${SCENARIO_RUNNER_ROOT}:${LEADERBOARD_ROOT}:${PYTHONPATH}

export force_color_prompt=yes

cd ScenarioGeneration

/bin/bash "$@"
