""" Runs a given scenario and makes a seed out of it.
Each car in the given scenario must have the following properties:
  route: the list of uid's of the lanes the car goes through
  signal: the turn signal the car uses throughout its route
"""
# imports
import importlib
from scenariogen.core.signals import SignalType
from scenic.core.vectors import Vector

# Load the given scenario
param scenario_path = None
scenario_path = globalParameters.scenario_path
initialSeed_module = importlib.import_module(scenario_path.replace('/', '.').replace('.scenic', ''))
initialSeed_scenario = initialSeed_module.InitialSeedScenario()
config = globalParameters.config # initialized by initialSeed_scenario
model globalParameters.model # initialized by initialSeed_scenario

# Import auxiliary scenarios
from scenariogen.core.scenarios import CheckCollisionsScenario, RecordSeedInfoScenario, RecordSimTrajectories, ShowIntersection


scenario Main():
  setup:
    p = network.elements[config['intersection']].polygon.centroid
    ego = Debris at Vector(p.x, p.y)

  compose:
    if globalParameters.save_sim_trajectories:
      do initialSeed_scenario, \
          CheckCollisionsScenario([], simulation().agents), \
          RecordSimTrajectories(simulation().agents), \
          ShowIntersection()
    else:      
      do initialSeed_scenario, \
          CheckCollisionsScenario([], simulation().agents), \
          RecordSeedInfoScenario(simulation().agents), \
          ShowIntersection()

