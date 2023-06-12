model scenic.simulators.newtonian.driving_model

param config = None
config = globalParameters.config

# Scenic imports
from scenarios import IntersectionEvents

# Python imports
from signals import SignalType

intersection = network.elements[config['intersection']]
cars = []
log = []

scenario Nonego(name, lane):
  setup:
    car = Car following roadDirection from lane.centerline[-1] for -5,
      with name name,
      with behavior FollowLaneBehavior(target_speed=4),
      with signal SignalType.OFF
    cars.append(car)

scenario Ego():
  ego = Car following roadDirection from intersection.incomingLanes[2].centerline[-1] for -20,
    with name 'ego',
    with behavior FollowLaneBehavior(target_speed=4),
    with signal SignalType.OFF,
    with physics True

scenario TestScenario():
  setup:
    sc0 = Ego()
    sc1 = Nonego('nonego', intersection.incomingLanes[3])
    sc2 = IntersectionEvents(intersection, cars, log)
    record final cars as cars
    record final log as events
  compose:
    do sc0, sc1, sc2


