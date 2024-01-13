
model scenic.domains.driving.model
config = globalParameters.config

from scenariogen.predicates.monitors import (ArrivingAtIntersectionMonitor,
                                             VehicleSignalMonitor,
                                             StoppingMonitor,
                                             RegionOverlapMonitor,
                                             OcclusionMonitor,
                                             CarlaCollisionMonitor,
                                             ActorsMonitor
                                            )

intersection = network.elements[config['intersection']]
trigger_regions = [intersection] + [m.connectingLane for m in intersection.maneuvers]

monitor EventsMonitor(eventsOut):
  require monitor VehicleSignalMonitor(config, eventsOut)
  require monitor ArrivingAtIntersectionMonitor({**config, 'network': network}, eventsOut)
  require monitor StoppingMonitor(config, eventsOut)
  require monitor RegionOverlapMonitor({**config, 'regions': trigger_regions}, eventsOut)
  require monitor OcclusionMonitor(config, eventsOut)
  require monitor CarlaCollisionMonitor(config, eventsOut)
  require monitor ActorsMonitor(config, eventsOut)

  while True:
    wait
