""" System Under Test (SUT)
Nonegos + optionally ego i.e. VUT (Vehicle Under Test)
"""

param config = None
config = globalParameters.config

model scenic.simulators.carla.model
from scenariogen.simulators.carla.monitors import ForbidEgoCollisionsMonitor, ShowIntersectionMonitor, LabelCarsMonitor
from scenariogen.simulators.carla.scenarios import NonegosScenario

nonegos_scenario = NonegosScenario(config)

# Plug-in Scenic modules
import importlib
intersection = network.elements[config['intersection']]
if config['ego_module']:
  ego_module = importlib.import_module(config['ego_module'])
  ego_scenario = ego_module.EgoScenario(config)

if config['coverage_module']:
  coverage_module = importlib.import_module(f"scenariogen.core.coverages.{config['coverage_module']}.monitor")
  coverage = coverage_module.Coverage([])

scenario Main():
  setup:
    if config['render_spectator'] or config['render_ego']:
      p = intersection.polygon.centroid
      ego = new Debris at p.x@p.y

    if config['coverage_module']:
      require monitor coverage_module.CoverageMonitor(coverage)
      record final coverage as coverage

    require monitor ForbidEgoCollisionsMonitor(config)
    if config['render_spectator']:
      require monitor ShowIntersectionMonitor(config['intersection'], label_lanes=True)

  compose:
    # Deterministic traffic manager with a common seed across all simulations so that autopilot's behavior is reproducible
    simulation().tm.set_random_device_seed(0)
   
    if config['ego_module']:
      do ego_scenario, \
          nonegos_scenario
    else:
      do nonegos_scenario

