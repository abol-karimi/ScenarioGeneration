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
from scenariogen.core.scenarios import NonegosScenario, CheckCollisionsScenario, ShowIntersection

if config['closedLoop']:
  ego_module = importlib.import_module(config['ego_module'])
  ego_scenario = ego_module.EgoScenario()

evaluate_coverage_module = importlib.import_module(config['coverage_module'])
evaluate_coverage_scenario = evaluate_coverage_module.EvaluateCoverageScenario()

nonegos_scenario = NonegosScenario()

scenario Main():
  setup:
    p = intersection.polygon.centroid
    ego = new Debris at p.x@p.y

    record initial config as config

  compose:
    if config['closedLoop']:
      do ego_scenario, \
          nonegos_scenario, \
          evaluate_coverage_scenario, \
          CheckCollisionsScenario(ego_scenario.cars, nonegos_scenario.cars), \
          ShowIntersection()
    else:
      do nonegos_scenario, \
          evaluate_coverage_scenario, \
          CheckCollisionsScenario([], nonegos_scenario.cars), \
          ShowIntersection()

