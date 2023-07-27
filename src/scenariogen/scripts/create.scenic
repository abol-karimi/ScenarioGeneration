""" Runs a given scenario and makes a seed out of it.
Each car in the given scenario must have the following properties:
  route: the list of uid's of the lanes the car goes through
  signal: the turn signal the car uses throughout its route
"""
# imports
import importlib
from scenariogen.core.signals import SignalType
from scenariogen.core.geometry import CurvilinearTransform

# Load the given scenario
param scenario_path = None
scenario_path = globalParameters.scenario_path
seed_module = importlib.import_module(scenario_path.replace('/', '.').replace('.scenic', ''))
seed_scenario = seed_module.SeedScenario()
config = globalParameters.config # initialized by seed_scenario
model globalParameters.model # initialized by seed_scenario

param save_sim_trajectories = None
save_sim_trajectories = globalParameters.save_sim_trajectories

# Import auxiliary scenarios
from scenariogen.core.scenarios import CheckCollisionsScenario, RecordSimTrajectories, ShowIntersection

transforms = []
footprints = []
routes = []
signals = []
lengths = []
widths = []

monitor RecordSeedInfoMonitor():
  cars = simulation().agents
  routes.extend(car.route for car in cars)
  transforms.extend(CurvilinearTransform([p for uid in route
                                            for p in network.elements[uid].centerline.lineString.coords
                                          ])
                    for route in routes)
  signals.extend(car.signal for car in cars)
  lengths.extend(car.length for car in cars)
  widths.extend(car.width for car in cars)
  while True:
    time = simulation().currentTime
    footprints.append((time, tuple(car.position for car in cars)))
    wait

# Record seed info
scenario Main():
  setup:
    p = network.elements[config['intersection']].polygon.centroid
    ego = new Debris at p.x@p.y

    require monitor RecordSeedInfoMonitor()
    record final config as config
    record final transforms as transforms
    record final footprints as footprints
    record final routes as routes
    record final signals as signals
    record final lengths as lengths
    record final widths as widths

  compose:
    if save_sim_trajectories:
      do seed_scenario, \
          CheckCollisionsScenario([], simulation().agents), \
          RecordSimTrajectories(simulation().agents), \
          ShowIntersection()
    else:      
      do seed_scenario, \
          ShowIntersection(), \
          CheckCollisionsScenario([], simulation().agents)


