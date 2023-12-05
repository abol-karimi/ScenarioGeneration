""" System Under Test (SUT)
Nonegos + optionally ego i.e. VUT (Vehicle Under Test)
"""

param config = None
config = globalParameters.config

model scenic.simulators.newtonian.driving_model
from scenariogen.simulators.newtonian.scenarios import NonegosScenario

nonegos_scenario = NonegosScenario(config)

# Plug-in Scenic modules
import importlib
intersection = network.elements[config['intersection']]
if config['ego_module']:
  ego_module = importlib.import_module(config['ego_module'])
  ego_scenario = ego_module.EgoScenario(config)

if config['coverage_module']:
  coverage_module = importlib.import_module(config['coverage_module'])
  coverage = coverage_module.Coverage([])

scenario Main():
  setup:
    if config['render_spectator'] or config['render_ego']:
      p = intersection.polygon.centroid
      ego = new Debris at p.x@p.y

    if config['coverage_module']:
      require monitor coverage_module.CoverageMonitor(coverage)
      record final coverage as coverage

  compose:  
    if config['ego_module']:
      do ego_scenario, \
          nonegos_scenario
    else:
      do nonegos_scenario

