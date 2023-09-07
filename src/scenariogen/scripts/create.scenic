""" Runs a given scenario and makes a seed out of it.
Each car in the given scenario must have the following properties:
  route: the list of uid's of the lanes the car goes through
  signal: the turn signal the car uses throughout its route
"""
# imports
import importlib
from scenariogen.core.geometry import CurvilinearTransform

param caller_config = None

# Load the given scenario
scenario_path = globalParameters.scenario_path
seed_module = importlib.import_module(scenario_path.replace('/', '.').replace('.scenic', ''))
config = seed_module.config
seed_scenario = seed_module.SeedScenario()
model scenic.simulators.carla.model # initialized by seed_module

param save_sim_trajectories = None
save_sim_trajectories = globalParameters.save_sim_trajectories

simulator_name = globalParameters.simulator

# Import auxiliary scenarios
from scenariogen.core.scenarios import RecordSimTrajectories
from scenariogen.simulators.carla.scenarios import ShowIntersectionScenario, RaiseEgoCollisionScenario

names = []
transforms = []
footprints = []
routes = []
signals = []
lengths = []
widths = []

# Record seed info
scenario Main():
  setup:
    # intersection = network.elements[seed_scenario.config['intersection']]
    # p = intersection.polygon.centroid
    # ego = Debris at p.x@p.y

    monitor RecordSeedInfoMonitor:
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

    record final config as config
    record final tuple(names) as names
    record final tuple(transforms) as transforms
    record final tuple(footprints) as footprints
    record final tuple(routes) as routes
    record final tuple(signals) as signals
    record final tuple(lengths) as lengths
    record final tuple(widths) as widths

  compose:
    intersection = network.elements[config['intersection']]
    nonegos = (a for a in simulation().agents if a.name != 'ego')
    egos = (a for a in simulation().agents if a.name == 'ego')
    
    if save_sim_trajectories:
      do seed_scenario, \
          RaiseEgoCollisionScenario(globalParameters.caller_config), \
          RecordSimTrajectories(cars), \
          ShowIntersectionScenario(intersection)
    else:      
      do seed_scenario, \
          RaiseEgoCollisionScenario(globalParameters.caller_config), \
          ShowIntersectionScenario(intersection)


