param config = None
config = globalParameters.config

if config['render-ego']:
  param render = True
else:
  param render = False

# Load the given scenario
import importlib
seed_module = importlib.import_module(config['scenario-file'].replace('/', '.').replace('.scenic', ''))
seed_config = seed_module.config
config.update(seed_config)

model scenic.simulators.carla.model
from scenariogen.simulators.carla.monitors import (ForbidEgoCollisionsMonitor,
                                                  ForbidNonegoCollisionsMonitor,
                                                  ShowIntersectionMonitor,
                                                  LabelCarsMonitor)


if 'coverage-module' in config and config['coverage-module']:
  coverage_module = importlib.import_module(f"scenariogen.core.coverages.{config['coverage-module']}")
  coverage_monitor = importlib.import_module(f"scenariogen.core.coverages.{config['coverage-module']}.monitor")
  coverage_events = []

from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.simulators.carla.utils import vehicleLightState_to_signal

names = []
blueprints = []
transforms = []
footprints = []
routes = []
signals = []

monitor RecordSeedInfoMonitor():
  for l in (names, blueprints, transforms, footprints, routes, signals):
    l.clear()

  nonegos = tuple(a for a in simulation().agents if a.name != 'ego')
  names.extend(nonego.name for nonego in nonegos)
  blueprints.extend(nonego.blueprint for nonego in nonegos)
  routes.extend(nonego.route for nonego in nonegos)
  transforms.extend(CurvilinearTransform([p for uid in route
                                            for p in network.elements[uid].centerline.lineString.coords
                                          ])
                    for route in routes)
  while True:
    time = simulation().currentTime
    footprints.append((time, tuple(nonego.position for nonego in nonegos)))
    signals.append((time, tuple(vehicleLightState_to_signal(nonego.carlaActor.get_light_state()) for nonego in nonegos))) # TODO Add signals to the driving domain
    wait

intersection = network.elements[seed_config['intersection']]

# Record seed info
scenario Main():
  setup:
    if config['render-ego']:
      p = intersection.polygon.centroid
      ego = new Debris at p.x@p.y
  
    require monitor RecordSeedInfoMonitor()
    if config['render-spectator']:
      require monitor ShowIntersectionMonitor(seed_config['intersection'],
                                              label_lanes=True,
                                              life_time=seed_config['timestep']*seed_config['steps']
                                             )
      require monitor LabelCarsMonitor()

    if 'coverage-module' in config and config['coverage-module']:
      require monitor coverage_monitor.EventsMonitor(coverage_events)
      record final coverage_events as events
      record final coverage_module.to_coverage(coverage_events, {**config, 'network': network}) as coverage
      
    record final seed_config as config
    record final tuple(names) as names
    record final tuple(blueprints) as blueprints
    record final tuple(transforms) as transforms
    record final tuple(footprints) as footprints
    record final tuple(routes) as routes
    record final tuple(signals) as signals

  compose:
    # Deterministic traffic manager with a common seed across all simulations so that autopilot's behavior is reproducible
    simulation().tm.set_random_device_seed(0)

    do seed_module.SeedScenario()
        



