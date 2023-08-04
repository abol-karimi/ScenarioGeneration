import math
import shapely
from scenic.core.vectors import Vector
from scenic.core.regions import PolylineRegion

def simplify(ps):
    """Removes overlapping segments of a polyline.
    Assumes that the curve does not bend more than 90 degrees.

    ps: list of points
    Returns: a sublist of ps
    """
    ps_simple = [ps[0], ps[1]]
    v0 = Vector(*ps_simple[-1]) - Vector(*ps_simple[-2])
    for i in range(2, len(ps)):
        v1 = Vector(*ps[i]) - Vector(*ps_simple[-1])
        if v0.dot(v1) >= 0:
            ps_simple.append(ps[i])
            v0 = v1
    return ps_simple

class CurvilinearTransform:
    """Transforms from a rectilinear frame to a curvilinear frame as defined by a polyline
    
    Attributes:
      axis is a polyline with rectilinear coordinates

    """
    def __init__(self, axis_coords):
        self.axis = PolylineRegion(points=simplify(axis_coords))
    
    def rectilinear(self, p):
        """Transforms coordinates from the curvilinear frame to the rectilienar frame."""
        proj = self.axis.lineString.interpolate(p[0])
        proj = Vector(proj.x, proj.y)
        start, end = self.axis.nearestSegmentTo(proj)
        tangent = (end - start).normalized()
        normal = tangent.rotatedBy(math.pi/2)
        position = proj + normal*p[1]
        return (position[0], position[1])
    
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
        normal = tangent.rotatedBy(math.pi/2)
        splitter = shapely.geometry.LineString([proj+normal, proj-normal])
        parts = shapely.ops.split(self.axis.lineString, splitter).geoms
        x = parts[0].length
        return (x, y)
