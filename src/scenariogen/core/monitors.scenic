model scenic.domains.driving.model

# Python imports
from itertools import combinations
import logging


monitor RejectOnAgentOverlapMonitor(overlap_threshold=1.0):
    logger = logging.getLogger(__name__)
    logger.info(f'Monitoring agent-agent overlap with threshold {overlap_threshold} ...')
    while True:
        for a, b in combinations(simulation().agents, 2):
            r1 = PolygonalRegion(polygon=a._boundingPolygon)
            r2 = PolygonalRegion(polygon=b._boundingPolygon)
            if r1.intersect(r2).size >= overlap_threshold:
                logger.info(f'Rejecting the simulation due to {a.name}-{b.name} overlap...')
                require False
        wait


monitor RequireAgentsBeInRoadMonitor():
    cars = simulation().agents
    while True:
        for car in cars:
            require car.position in road
        wait
