""" System Under Test (SUT)
Nonegos + optionally ego i.e. VUT (Vehicle Under Test)
"""

param config = None
config = globalParameters.config

# imports
import importlib
from scenariogen.core.scenarios import NonegosScenario

# Simulator-specific settings
if config['simulator'] == 'carla':
  model scenic.simulators.carla.model
  from scenariogen.simulators.carla.monitors import RaiseEgoCollisionMonitor, ShowIntersectionMonitor, LabelCarsMonitor
elif config['simulator'] == 'newtonian':
  model scenic.simulators.newtonian.driving_model
else:
  model scenic.domains.driving.model

intersection = network.elements[config['intersection']]
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

    if config['simulator'] == 'carla':
      require monitor RaiseEgoCollisionMonitor(config)
      if config['render_spectator']:
        require monitor ShowIntersectionMonitor(config['intersection'], label_lanes=True)
    require monitor coverage_monitor

    record initial config as config # needed?
    record final coverage_space as coverage_space
    record final coverage_module.coverage as coverage

  compose:
    if config['closedLoop']:
      do ego_scenario, \
          nonegos_scenario
    else:
      do nonegos_scenario

