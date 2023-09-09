param caller_config = None
caller_config = globalParameters.caller_config

# Load the given scenario
scenario_path = globalParameters.scenario_path
import importlib
seed_module = importlib.import_module(scenario_path.replace('/', '.').replace('.scenic', ''))
config = seed_module.config
seed_scenario = seed_module.SeedScenario()
model scenic.simulators.carla.model

param save_sim_trajectories = None
save_sim_trajectories = globalParameters.save_sim_trajectories

# Import auxiliary scenarios
from scenariogen.simulators.carla.monitors import ShowIntersectionMonitor, RaiseEgoCollisionMonitor
from scenariogen.core.geometry import CurvilinearTransform

names = []
transforms = []
footprints = []
routes = []
signals = []
lengths = []
widths = []

monitor RecordSeedInfoMonitor():
  nonegos = tuple(a for a in simulation().agents if a.name != 'ego')
  names.extend(car.name for car in nonegos)
  routes.extend(car.route for car in nonegos)
  transforms.extend(CurvilinearTransform([p for uid in route
                                            for p in network.elements[uid].centerline.lineString.coords
                                          ])
                    for route in routes)
  signals.extend(car.signal for car in nonegos)
  lengths.extend(car.length for car in nonegos)
  widths.extend(car.width for car in nonegos)
  while True:
    time = simulation().currentTime
    footprints.append((time, tuple(car.position for car in nonegos)))
    wait

intersection = network.elements[config['intersection']]

# Record seed info
scenario Main():
  setup:
    p = intersection.polygon.centroid
    ego = new Debris at p.x@p.y
  
    require monitor RecordSeedInfoMonitor()
    require monitor RaiseEgoCollisionMonitor(caller_config)
    if caller_config['render']:
      require monitor ShowIntersectionMonitor(intersection)

    record final config as config
    record final tuple(names) as names
    record final tuple(transforms) as transforms
    record final tuple(footprints) as footprints
    record final tuple(routes) as routes
    record final tuple(signals) as signals
    record final tuple(lengths) as lengths
    record final tuple(widths) as widths

  compose:
    do seed_scenario
        



