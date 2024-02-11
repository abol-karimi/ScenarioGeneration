model scenic.domains.driving.model

# Python imports
from itertools import combinations

monitor RejectOnAgentOverlapMonitor(overlap_threshold=1.0):
  while True:
    for a, b in combinations(simulation().agents, 2):
      r1 = PolygonalRegion(polygon=a._boundingPolygon)
      r2 = PolygonalRegion(polygon=b._boundingPolygon)
      if r1.intersect(r2).size >= overlap_threshold:
        print('Rejecting the simulation due to agent-agent overlap...')
        require False
    wait


monitor RequireAgentsBeInRoadMonitor():
  cars = simulation().agents
  while True:
    for car in cars:
      require car.position in road
    wait
