""" System Under Test (SUT)
Nonegos + optionally ego i.e. VUT (Vehicle Under Test)
"""

# Scenic parameters
model scenic.domains.driving.model
param config = None
config = globalParameters.config
intersection = network.elements[config['intersection']]

# imports
import importlib
from scenariogen.core.signals import SignalType
from scenic.core.vectors import Vector
from scenariogen.core.scenarios import NonegosScenario, RecordEventsScenario, CheckCollisionsScenario

# The module specifying VUT
ego_module = importlib.import_module(config['ego_module'])

if config['closedLoop']:
  ego_scenario = ego_module.EgoScenario()

nonegos_scenario = NonegosScenario()

scenario Main():
  setup:
    p = intersection.polygon.centroid
    ego = Debris at Vector(p.x, p.y)

  compose:
    if config['closedLoop']:
      do ego_scenario, \
          nonegos_scenario, \
          RecordEventsScenario(ego_scenario.cars), \
          RecordEventsScenario(nonegos_scenario.cars), \
          CheckCollisionsScenario(ego_scenario.cars, nonegos_scenario.cars)
    else:
      do nonegos_scenario, \
          RecordEventsScenario(nonegos_scenario.cars), \
          CheckCollisionsScenario([], nonegos_scenario.cars)

