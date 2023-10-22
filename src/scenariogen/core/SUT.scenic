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
  from scenariogen.simulators.carla.monitors import ForbidEgoCollisionsMonitor, ShowIntersectionMonitor, LabelCarsMonitor
elif config['simulator'] == 'newtonian':
  model scenic.simulators.newtonian.driving_model
else:
  model scenic.domains.driving.model

intersection = network.elements[config['intersection']]
if config['closedLoop']:
  ego_module = importlib.import_module(config['ego_module'])
  ego_scenario = ego_module.EgoScenario(config)

nonegos_scenario = NonegosScenario(config)

if config['coverage_module']:
  coverage_module = importlib.import_module(config['coverage_module'])
  coverage = coverage_module.Coverage([])

scenario Main():
  setup:
    if config['render_ego']:
      p = intersection.polygon.centroid
      ego = new Debris at p.x@p.y

    if config['coverage_module']:
      require monitor coverage_module.CoverageMonitor(coverage)
      record final coverage as coverage

    if config['simulator'] == 'carla':
      require monitor ForbidEgoCollisionsMonitor(config)
      if config['render_spectator']:
        require monitor ShowIntersectionMonitor(config['intersection'], label_lanes=True)

  compose:
    if config['simulator'] == 'carla':
      # Deterministic traffic manager with a common seed across all simulations so that autopilot's behavior is reproducible
      simulation().tm.set_random_device_seed(0)
   
    if config['closedLoop']:
      do ego_scenario, \
          nonegos_scenario
    else:
      do nonegos_scenario

