# Scenic parameters
model scenic.domains.driving.model
param config = None
config = globalParameters.config

# imports
from scenariogen.core.signals import SignalType

def withinDistanceToCarsOnRoute(vehicle, route_lanes, thresholdDistance):
  """ checks whether there exists any obj
  (1) in front of the vehicle, (2) on the same route, (3) within thresholdDistance """
  cars = (o for o in simulation().objects if isinstance(o, Vehicle) and not o is vehicle)
  for car in cars:
    p2p_distance = distance from vehicle.position to car.position
    if p2p_distance > thresholdDistance: # cheap-to-compute sufficient condition
      continue 
    if not (vehicle can see car):
      continue
    for lane in route_lanes:
      if not car.intersects(lane): # not on route
        continue
      if (distance from vehicle to car) <= thresholdDistance:
        return True
  return False

behavior FollowRouteAvoidCollisionsBehavior(target_speed, route_lanes):
  try:
    do FollowTrajectoryBehavior(target_speed, route_lanes)
  interrupt when withinDistanceToCarsOnRoute(self, route_lanes, 10):
    take SetBrakeAction(1)

  # Stop at the end of the route
  take SetThrottleAction(0), SetBrakeAction(1)

scenario EgoScenario():
  setup:
    ego_lanes = [network.elements[l] for l in config['ego_route']]
    ego_centerline = PolylineRegion.unionAll([l.centerline for l in ego_lanes])
    ego_init_pos = ego_centerline.pointAlongBy(config['ego_init_progress'])
    ego = Car at ego_init_pos,
      with name 'ego',
      with width 2.163450002670288,
      with length 4.791779518127441,
      with blueprint 'vehicle.tesla.model3',
      with signal SignalType.OFF,
      with behavior FollowRouteAvoidCollisionsBehavior(6, ego_lanes)
    cars = [ego]

