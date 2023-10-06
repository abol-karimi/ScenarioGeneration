

monitor IntersectionArrivalMonitor(intersection, arrival_distance, eventsOut):
  """
  Informal definition of an intersection arrival event:
    1. At the initial time step, no car has arrived. (Events happen on transitions, but at the beginning, no transitions have been observed yet.)
    2. At an arrival event, the front of the car is on an incoming lane to the intersection.
    2. At an arrival event, the distance of front of the car to the intersection is at most `arrival_distance`.
    3. At the time step prior to an arrival event, the distance of the front of the car to the intersection is bigger than `arrival_distance`.
  """
  cars = simulation().agents
  incomingLanes = set(lane.uid for lane in intersection.incomingLanes)
  for i in range(len(incomingLanes)):


  arrived = {car: False for car in cars}
