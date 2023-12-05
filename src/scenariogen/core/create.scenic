param caller_config = None
caller_config = globalParameters.caller_config

# Load the given scenario
import importlib
seed_module = importlib.import_module(caller_config['scenario_path'].replace('/', '.').replace('.scenic', ''))
seed_config = seed_module.config

# Simulator-specific settings
if caller_config['simulator'] == 'carla':
  model scenic.simulators.carla.model
  from scenariogen.simulators.carla.monitors import (ForbidEgoCollisionsMonitor,
                                                    ForbidNonegoCollisionsMonitor,
                                                    ShowIntersectionMonitor,
                                                    LabelCarsMonitor)
  if caller_config['render_ego']:
    param render = True
  else:
    param render = False
elif caller_config['simulator'] == 'newtonian':
  model scenic.simulators.newtonian.driving_model
  if not caller_config['render_spectator']:
    param render = False

from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.simulators.carla.utils import vehicleLightState_to_signal # TODO add vehicle signal to Scenic

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
    if caller_config['render_spectator'] or caller_config['render_ego']:
      p = intersection.polygon.centroid
      ego = new Debris at p.x@p.y
  
    require monitor RecordSeedInfoMonitor()
    if caller_config['simulator'] == 'carla':
      require monitor ForbidEgoCollisionsMonitor(seed_config)
      require monitor ForbidNonegoCollisionsMonitor(seed_config)
      if caller_config['render_spectator']:
        require monitor ShowIntersectionMonitor(seed_config['intersection'], label_lanes=True)
        require monitor LabelCarsMonitor()

    record final seed_config as config
    record final tuple(names) as names
    record final tuple(blueprints) as blueprints
    record final tuple(transforms) as transforms
    record final tuple(footprints) as footprints
    record final tuple(routes) as routes
    record final tuple(signals) as signals

  compose:
    if caller_config['simulator'] == 'carla':
      # Deterministic traffic manager with a common seed across all simulations so that autopilot's behavior is reproducible
      simulation().tm.set_random_device_seed(0)

    do seed_module.SeedScenario()
        



