param caller_config = None
caller_config = globalParameters.caller_config

# Load the given scenario
import importlib
seed_module = importlib.import_module(caller_config['scenario-file'].replace('/', '.').replace('.scenic', ''))
seed_config = seed_module.config

# Specify the simulator model after importing seed_module since it specifies the map
model scenic.simulators.newtonian.driving_model
if not caller_config['render-spectator']:
  param render = False

from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.core.signals import SignalType

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
    signals.append((time, tuple(SignalType.OFF for nonego in nonegos)))
    wait

intersection = network.elements[seed_config['intersection']]

# Record seed info
scenario Main():
  setup:
    if caller_config['render-spectator']:
      p = intersection.polygon.centroid
      ego = new Debris at p.x@p.y
  
    require monitor RecordSeedInfoMonitor()

    record final seed_config as config
    record final tuple(names) as names
    record final tuple(blueprints) as blueprints
    record final tuple(transforms) as transforms
    record final tuple(footprints) as footprints
    record final tuple(routes) as routes
    record final tuple(signals) as signals

  compose:
    do seed_module.SeedScenario()
        



