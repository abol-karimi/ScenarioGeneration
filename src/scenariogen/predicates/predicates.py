from scenariogen.core.signals import SignalType


def geometry_atoms(network, intersection_uid):
    intersection = network.elements[intersection_uid]
    maneuvers = intersection.maneuvers
    geometry = []
    geometry.extend(f'incomingLane({lane.uid})' for lane in intersection.incomingLanes)
    geometry.extend(f'connectingLane({m.connectingLane.uid})' for m in maneuvers)
    geometry.extend(f'outgoingLane({lane.uid})' for lane in intersection.outgoingLanes)

    for m in intersection.maneuvers:
        geometry.append(f'lanePrecedes({m.startLane.uid}, {m.connectingLane.uid})')
        geometry.append(f'lanePrecedes({m.connectingLane.uid}, {m.endLane.uid})')


    for maneuver in maneuvers:
        lane = maneuver.connectingLane
        signal = SignalType.from_maneuver_type(maneuver.type).name.lower()
        geometry.append(
            f'laneCorrectSignal({lane.uid}, {signal})')

    for i in range(len(maneuvers)):
        li = maneuvers[i].connectingLane
        geometry.append(f'overlaps({li.uid}, {li.uid})')
        for j in range(i+1, len(maneuvers)):
            lj = maneuvers[j].connectingLane
            if li.intersects(lj):
                geometry.append(f'overlaps({li.uid}, {lj.uid})')
                geometry.append(f'overlaps({lj.uid}, {li.uid})')

    roads = intersection.roads
    incomings = intersection.incomingLanes
    road2incomings = {road.uid: [] for road in roads}
    for incoming in incomings:
        road2incomings[incoming.road.uid].append(incoming.uid)
    # An intersection stores the intersecting roads in CW or CCW order.
    # Assuming the order is CCW, then:
    import math
    for i in range(len(roads)):
        ii = (i+1) % len(roads)  # cyclic order
        lefts = road2incomings[roads[i].uid]
        rights = road2incomings[roads[ii].uid]
        l0 = network.elements[lefts[0]]
        r0 = network.elements[rights[0]]
        hl = l0.centerline[-1] - l0.centerline[-2]  # heading
        hr = r0.centerline[-1] - r0.centerline[-2]  # heading
        # Ignore roads on opposing directions:
        if abs(math.pi - abs(hr.angleWith(hl))) < math.pi/6:
            continue
        geometry += [
            f'isOnRightOf({right}, {left})' for left in lefts for right in rights]
    
    # Patching Scenic's geometry model
    if intersection_uid in {'intersection1930', 'intersection396'}:
        for lane in intersection.incomingLanes:
            geometry.append(f'hasStopSign({lane.uid})')
            
    return geometry