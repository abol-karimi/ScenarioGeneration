
model scenic.domains.driving.model
config = globalParameters.config

from scenariogen.predicates.monitors import (ArrivingAtIntersectionMonitor,
                                             StoppingMonitor,
                                             RegionOverlapMonitor,
                                             AgentsMonitor
                                            )

intersection = network.elements[config['intersection']]
trigger_regions = [intersection] + [m.connectingLane for m in intersection.maneuvers]

monitor EventsMonitor(eventsOut):
    require monitor ArrivingAtIntersectionMonitor({**config, 'network': network}, eventsOut)
    require monitor StoppingMonitor(config, eventsOut)
    require monitor RegionOverlapMonitor({**config, 'regions': trigger_regions}, eventsOut)
    require monitor AgentsMonitor(config, eventsOut)

    eventsOut.clear()

    while True:
        wait
