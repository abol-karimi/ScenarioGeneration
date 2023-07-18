import math
import shapely
from shapely.geometry import LineString
from scenic.core.vectors import Vector
from scenic.core.regions import PolylineRegion
from scenic.core.object_types import OrientedPoint
from scenic.core.geometry import headingOfSegment

# This project
from scenariogen.core.utils import simplify

class CurvilinearTransform:
    """Transforms from a rectilinear frame to a curvilinear frame as defined by a polyline
    
    Attributes:
      axis is a polyline with rectilinear coordinates

    """
    def __init__(self, axis_coords):
        self.axis = PolylineRegion(points=simplify(axis_coords))
    
    def rectilinear(self, pose : OrientedPoint):
        """Transforms coordinates from the curvilinear frame to the rectilienar frame."""
        proj = self.axis.lineString.interpolate(pose.position[0])
        proj = Vector(proj.x, proj.y)
        start, end = self.axis.nearestSegmentTo(proj)
        tangent = (end - start).normalized()
        normal = tangent.rotatedBy(math.pi/2)
        position = proj + normal*pose.position[1]
        heading = headingOfSegment(start, end) + pose.heading
        return OrientedPoint(position=position, heading=heading)
    
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
