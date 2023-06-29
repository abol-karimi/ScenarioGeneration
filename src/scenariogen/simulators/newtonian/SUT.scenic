
# Scenic parameters
model scenic.simulators.newtonian.driving_model
param config = None
config = globalParameters.config
intersection = network.elements[config['intersection']]

# imports
from scenic.core.vectors import Vector
from scenariogen.simulators.newtonian.scenarios import NonegosScenario, RecordEventsScenario
import importlib
ego_module = importlib.import_module(config['ego_module'])

if config['closedLoop']:
  ego_scenario = ego_module.EgoScenario()

nonegos_scenario = NonegosScenario()

scenario Main():
  setup:
    p = intersection.polygon.centroid
    ego = Object at Vector(p.x, p.y),
            with name 'dummy',
            with physics False,
            with allowCollisions True
  compose:
    if config['closedLoop']:
      do ego_scenario, nonegos_scenario, RecordEventsScenario(ego_scenario.cars), RecordEventsScenario(nonegos_scenario.cars)
    else:
      do nonegos_scenario, RecordEventsScenario(nonegos_scenario.cars)


# monitor collisions:
#   nonego_pairs = [(nonegos[i], nonegos[j]) 
#            for i in range(len(nonegos)) 
#            for j in range(i+1, len(nonegos))]
#   while True:
#     for c, d in nonego_pairs:
#       if c.intersects(d):
#         raise InvalidSeedError
#     for nonego in nonegos:
#       if nonego.intersects(self.ego):
#         raise EgoCollisionError
#     wait
