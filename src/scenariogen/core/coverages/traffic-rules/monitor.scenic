
model scenic.domains.driving.model
config = globalParameters.config

from scenariogen.predicates.monitors import (ArrivingAtIntersectionMonitor,
                                                StoppingMonitor,
                                                RegionOverlapMonitor,
                                                AgentsMonitor,
                                                CarlaVehicleSignalMonitor,
                                                CarlaCollisionMonitor,
                                                NewtonianVehicleSignalMonitor,
                                                NewtonianCollisionMonitor
                                            )

intersection = network.elements[config['intersection']]
trigger_regions = [intersection] + [m.connectingLane for m in intersection.maneuvers]

monitor EventsMonitor(eventsOut):
    if config['simulator'] == 'carla':
        require monitor CarlaVehicleSignalMonitor(config, eventsOut)
        require monitor CarlaCollisionMonitor(config, eventsOut)
    elif config['simulator'] == 'newtonian':
        require monitor NewtonianVehicleSignalMonitor({**config, 'network': network}, eventsOut)
        require monitor NewtonianCollisionMonitor(config, eventsOut)

    require monitor ArrivingAtIntersectionMonitor({**config, 'network': network}, eventsOut)
    require monitor StoppingMonitor(config, eventsOut)
    require monitor RegionOverlapMonitor({**config, 'regions': trigger_regions}, eventsOut)
    require monitor AgentsMonitor(config, eventsOut)

    eventsOut.clear()

    while True:
        wait
