# Scenic parameters
model scenic.simulators.carla.model
param config = None
config = globalParameters.config

# imports
from tests.compose.scenarios_carla import NonegosScenario, DummyScenario, RecordEvents

if config['ego']:
  ego_scenario = config['ego_scenario']
else:
  ego_scenario = DummyScenario()

nonegos_scenario = NonegosScenario()

scenario SUTScenario():
  compose:
    ego = ego_scenario.egoObject
    if config['ego']:
      do nonegos_scenario, ego_scenario, RecordEvents([ego]+nonegos_scenario.cars)
    else:
      do nonegos_scenario, ego_scenario, RecordEvents(nonegos_scenario.cars)
