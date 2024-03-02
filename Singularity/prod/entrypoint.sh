#--------------------------------------
#---------- Set bash's state ----------
#--------------------------------------

# Python
. /home/scenariogen/.venv/bin/activate

# Carla
export CARLA_ROOT='/home/scenariogen/carla'
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/agents/:$PYTHONPATH
export PYTHONPATH=${CARLA_ROOT}/PythonAPI/carla/dist/${carla_egg}:$PYTHONPATH

# ScenarioGeneneration
export PYTHONPATH=/home/scenariogen/ScenarioGeneration/src/:$PYTHONPATH
export PYTHONPATH=/home/scenariogen/ScenarioGeneration/:$PYTHONPATH
export PATH=/home/scenariogen/ScenarioGeneration/:$PATH
export PATH=/home/scenariogen/ScenarioGeneration/tests/:$PATH
export PATH=/home/scenariogen/ScenarioGeneration/src/scenariogen/scripts/:$PATH
export PATH=/home/scenariogen/ScenarioGeneration/src/scenariogen/scripts/carla:$PATH
export PATH=/home/scenariogen/ScenarioGeneration/src/scenariogen/scripts/newtonian:$PATH
export PATH=/home/scenariogen/z3-4.8.10-x64-ubuntu-18.04/bin:$PATH

# ScenarioComplexity
export PYTHONPATH=/home/scenariogen/ScenarioComplexity/src/:$PYTHONPATH
export PYTHONPATH=/home/scenariogen/ScenarioComplexity/:$PYTHONPATH
export PATH=$PATH:/home/scenariogen/ScenarioComplexity/src/complexgen/scripts/

# TF++ AV agent
export WORK_DIR=/home/scenariogen/carla_garage_fork
export SCENARIO_RUNNER_ROOT=${WORK_DIR}/scenario_runner
export LEADERBOARD_ROOT=${WORK_DIR}/leaderboard
export PYTHONPATH=${WORK_DIR}:${WORK_DIR}/team_code:${SCENARIO_RUNNER_ROOT}:${LEADERBOARD_ROOT}:${PYTHONPATH}

# bash prompt
export force_color_prompt=yes

cd /home/scenariogen/ScenarioGeneration

/bin/bash "$@"
