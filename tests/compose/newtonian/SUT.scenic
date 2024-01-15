# Scenic parameters
model scenic.simulators.newtonian.driving_model
param config = None
config = globalParameters.config

# imports
from tests.compose.newtonian.scenarios import NonegosScenario, DummyScenario, RecordEvents
import importlib
ego_module = importlib.import_module(config['ego-module'])

if config['ego']:
  ego_scenario = ego_module.EgoScenario()

nonegos_scenario = NonegosScenario()

scenario SUTScenario():
  setup:
    ego = Car
  compose:
    if config['ego']:
      do ego_scenario, nonegos_scenario, RecordEvents(ego_scenario.cars), RecordEvents(nonegos_scenario.cars)
    else:
      do nonegos_scenario, RecordEvents(nonegos_scenario.cars)
