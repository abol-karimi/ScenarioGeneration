# Scenic parameters
model scenic.simulators.newtonian.driving_model

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
      if not car.occupiedSpace.intersects(lane.footprint): # not on route
        continue
      if (distance from vehicle to car) <= thresholdDistance:
        return True
  return False
  
behavior FollowRouteAvoidCollisionsBehavior(route_lanes, target_speed=4):
  try:
    do FollowTrajectoryBehavior(target_speed, route_lanes)
  interrupt when withinDistanceToCarsOnRoute(self, route_lanes, 10):
    take SetBrakeAction(1)

  # Stop at the end of the route
  take SetThrottleAction(0), SetBrakeAction(1)

behavior StopBehavior():
  take SetThrottleAction(0)
  take SetBrakeAction(1)
  while True:
    wait

behavior FourWayStopBehavior(route_lanes, target_speed=6, arrival_distance=5):
  do FollowRouteAvoidCollisionsBehavior(route_lanes, target_speed)\
      until (distance from (front of self) to intersection) <= arrival_distance
  do StopBehavior() until self.speed <= 0.1
  do FollowRouteAvoidCollisionsBehavior(route_lanes, target_speed)
  do FollowLaneBehavior(target_speed)