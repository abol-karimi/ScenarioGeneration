import math
import shapely
from scenic.core.vectors import Vector
from scenic.core.regions import PolylineRegion

def simplify(points):
    """Removes overlapping segments of a polyline.
    Assumes that the curve does not bend more than 90 degrees.

    ps: list of points
    Returns: a sublist of ps
    """
    vs = tuple(Vector(*p[:2]) for p in points)
    vs_simple = [vs[0], vs[1]]
    dv0 = vs_simple[-1] - vs_simple[-2]
    for i in range(2, len(vs)):
        dv1 = vs[i] - vs_simple[-1]
        if dv0.dot(dv1) >= 0:
            vs_simple.append(vs[i])
            dv0 = dv1
        else:
            print(f"Excluding the {i}th point of the polyline from the curvilinear-transform's axis.")
    return vs_simple

class CurvilinearTransform:
    """Transforms from a rectilinear frame to a curvilinear frame as defined by a polyline
    
    Attributes:
      axis is a polyline with rectilinear coordinates

    """
    def __init__(self, axis_coords):
        self.axis = PolylineRegion(points=simplify(axis_coords))
    
    def rectilinear(self, p, heading=0):
        """Transforms coordinates from the curvilinear frame to the rectilienar frame."""
        proj = self.axis.lineString.interpolate(p[0])
        proj = Vector(proj.x, proj.y)
        start, end = self.axis.nearestSegmentTo(proj)
        tangent = (end - start).normalized()
        normal = tangent.rotatedBy(math.pi/2)
        position = proj + normal*p[1]
        north = Vector(0,1)
        return (position[0], position[1], north.angleWith(tangent) + heading)
    
    def curvilinear(self, p):
        """Transforms coordinates from the rectilinear frame to the curvilinear frame.
        """
        v = Vector(p[0], p[1])
        proj = self.axis.project(v)
        proj = Vector(proj.x, proj.y)
        dist = v.distanceTo(proj)
        start, end = self.axis.nearestSegmentTo(proj)
        tangent = (end - start).normalized()
        y = dist if tangent.angleWith(v - start) >= 0 else -dist
        x = shapely.line_locate_point(self.axis.lineString, shapely.Point(proj[0], proj[1]))
        return (float(x), float(y))
