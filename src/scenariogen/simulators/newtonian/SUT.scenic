""" System Under Test (SUT)
Nonegos + optionally ego i.e. VUT (Vehicle Under Test) + optionally a coverage monitor
"""

param config = None
config = globalParameters.config

model scenic.simulators.newtonian.driving_model
from scenariogen.simulators.newtonian.scenarios import NonegosScenario

nonegos_scenario = NonegosScenario(config)

# Plug-in Scenic modules
import jsonpickle
import importlib
intersection = network.elements[config['intersection']]
if config['ego-module']:
  ego_module = importlib.import_module(config['ego-module'])
  ego_behavior = ego_module.ego_behavior

if 'coverage-module' in config and config['coverage-module']:
  coverage_module = importlib.import_module(f"scenariogen.core.coverages.{config['coverage-module']}")
  coverage_monitor = importlib.import_module(f"scenariogen.core.coverages.{config['coverage-module']}.monitor")
  coverage_events = []

scenario Main():
  setup:
    if config['ego-module']:
      with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'r') as f:
        blueprint2dims = jsonpickle.decode(f.read())
      lanes = [network.elements[l] for l in config['ego_route']]
      centerline = PolylineRegion.unionAll([l.centerline for l in lanes])
      init_pos = centerline.pointAlongBy(config['ego_init_progress_ratio']*centerline.length)
      blueprint = config['ego_blueprint']
      ego = new Car at init_pos,
        with name 'ego',
        with rolename 'hero',
        with color Color(0, 1, 0),
        with blueprint blueprint,
        with width blueprint2dims[blueprint]['width'],
        with length blueprint2dims[blueprint]['length'],
        with behavior ego_behavior,
        with physics True,
        with allowCollisions False
    
    elif config['render-spectator'] or config['render-ego']:
      p = intersection.polygon.centroid
      ego = new Debris at p.x@p.y

    if 'coverage-module' in config and config['coverage-module']:
      require monitor coverage_module.EventsMonitor(coverage_events)
      record final coverage_module.to_coverage(coverage_events, {**config, 'network': network}) as coverage
      record final coverage_events as events     

  compose:  
    do nonegos_scenario

