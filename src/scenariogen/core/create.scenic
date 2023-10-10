param caller_config = None
caller_config = globalParameters.caller_config

# Load the given scenario
import importlib
seed_module = importlib.import_module(caller_config['scenario_path'].replace('/', '.').replace('.scenic', ''))
seed_config = seed_module.config
# seed_scenario = seed_module.SeedScenario()
if 'simulator_name' in caller_config:
  simulator_name = caller_config['simulator_name']
  if not simulator_name in seed_config['compatible_simulators']:
    raise ValueError(f'Requested simulator {simulator_name} not supported by the seed.')
else:
  simulator_name = seed_config['compatible_simulators'][0]

# Simulator-specific settings
if simulator_name == 'carla':
  model scenic.simulators.carla.model
  from scenariogen.simulators.carla.monitors import (ForbidEgoCollisionsMonitor,
                                                    ForbidNonegoCollisionsMonitor,
                                                    ShowIntersectionMonitor,
                                                    LabelCarsMonitor)
  if caller_config['render_ego']:
    param render = True
  else:
    param render = False
elif simulator_name == 'newtonian':
  model scenic.simulators.newtonian.driving_model
  if not caller_config['render_spectator']:
    param render = False

from scenariogen.core.geometry import CurvilinearTransform
from scenariogen.core.monitors import RequireOnRoadMonitor
from scenariogen.simulators.carla.utils import vehicleLightState_to_signal # TODO add vehicle signal to Scenic

names = []
blueprints = []
transforms = []
footprints = []
routes = []
signals = []

monitor RecordSeedInfoMonitor():
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
    if caller_config['render_ego']:
      p = intersection.polygon.centroid
      ego = new Debris at p.x@p.y
  
    # require monitor RequireOnRoadMonitor()
    require monitor RecordSeedInfoMonitor()
    if simulator_name == 'carla':
      require monitor ForbidEgoCollisionsMonitor(seed_config)
      require monitor ForbidNonegoCollisionsMonitor(seed_config)
      if caller_config['render_spectator']:
        require monitor ShowIntersectionMonitor(seed_config['intersection'], label_lanes=False)
        # require monitor LabelCarsMonitor()

    record final seed_config as config
    record final tuple(names) as names
    record final tuple(blueprints) as blueprints
    record final tuple(transforms) as transforms
    record final tuple(footprints) as footprints
    record final tuple(routes) as routes
    record final tuple(signals) as signals

  compose:
    do seed_module.SeedScenario()
        



