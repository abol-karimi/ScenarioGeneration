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
from scenariogen.core.scenarios import NonegosScenario
from scenariogen.simulators.carla.monitors import ShowIntersectionMonitor

if config['closedLoop']:
  ego_module = importlib.import_module(config['ego_module'])
  ego_scenario = ego_module.EgoScenario(config)

nonegos_scenario = NonegosScenario(config)

coverage_module = importlib.import_module(config['coverage_module'])
coverage_space = coverage_module.coverage_space
coverage_monitor = coverage_module.CoverageMonitor()

scenario Main():
  setup:
    p = intersection.polygon.centroid
    ego = new Debris at p.x@p.y

    require monitor ShowIntersectionMonitor(intersection)
    require monitor coverage_monitor

    record initial config as config
    record final coverage_space as coverage_space
    record final coverage_module.coverage as coverage

  compose:
    if config['closedLoop']:
      do ego_scenario, \
          nonegos_scenario
    else:
      do nonegos_scenario

