""" Scenario Description
Ego-vehicle arrives at an intersection.
"""

# Scenic parameters
model scenic.simulators.newtonian.driving_model

# Python imports
from scenarios import EgoFollowingLanes, Nonegos, IntersectionEvents
from signals import SignalType

param config = None
config = globalParameters.config

# Derived constants
intersection = network.elements[config['intersection']]
seed = config['seed']
seconds = seed.trajectories[0].ctrlpts[-1][2]
steps = int(seconds / config['timestep'])

# Bookkeeping
cars = []

# Output
events = []

#--- Ego (VUT) in the loop
scenario ClosedLoop():
  setup:
    ego_lanes = [network.elements[l] for l in config['ego_route'].lanes]
    ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
    ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress'])
    ego = Car at ego_init_pos,
              with name 'ego',
              with color Color(0, 1, 0),
              with behavior FollowLaneBehavior(target_speed=4),
              with physics True,
              with allowCollisions False,
              with signal SignalType.OFF
    cars.append(ego)
    record final events as events
  compose:
    do Nonegos(cars), IntersectionEvents(intersection, cars, events)

#--- Only nonegos
scenario OpenLoop():
  setup:
    ego = Car at 0@0,
            with name 'dummy',
            with physics False,
            with allowCollisions True,
            with color Color(1, 1, 1)
    record final events as events
  compose:
    do Nonegos(cars), IntersectionEvents(intersection, cars, events)
