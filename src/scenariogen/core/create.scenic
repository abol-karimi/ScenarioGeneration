param caller_config = None
caller_config = globalParameters.caller_config

# Load the given scenario
scenario_path = globalParameters.scenario_path
import importlib
seed_module = importlib.import_module(scenario_path.replace('/', '.').replace('.scenic', ''))
config = seed_module.config
seed_scenario = seed_module.SeedScenario()
if config['simulator'] == 'carla':
  model scenic.simulators.carla.model
elif config['simulator'] == 'newtonian':
  model scenic.simulators.newtonian.driving_model
else:
  model scenic.domains.driving.model

param save_sim_trajectories = None
save_sim_trajectories = globalParameters.save_sim_trajectories

# Import auxiliary scenarios
from scenariogen.simulators.carla.monitors import ShowIntersectionMonitor, RaiseEgoCollisionMonitor, LabelCarsMonitor
from scenariogen.core.geometry import CurvilinearTransform

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
  signals.extend(nonego.signal for nonego in nonegos)
  while True:
    time = simulation().currentTime
    footprints.append((time, tuple(nonego.position for nonego in nonegos)))
    wait

intersection = network.elements[config['intersection']]

# Record seed info
scenario Main():
  setup:
    p = intersection.polygon.centroid
    ego = new Debris at p.x@p.y
  
    require monitor RecordSeedInfoMonitor()
    require monitor RaiseEgoCollisionMonitor(config)
    if caller_config['render_spectator']:
      require monitor ShowIntersectionMonitor(intersection, label_lanes=True)
      require monitor LabelCarsMonitor()

    record final config as config
    record final tuple(names) as names
    record final tuple(blueprints) as blueprints
    record final tuple(transforms) as transforms
    record final tuple(footprints) as footprints
    record final tuple(routes) as routes
    record final tuple(signals) as signals

  compose:
    do seed_scenario
        



