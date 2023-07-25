#!/usr/bin/env python3.8

# External libraries
from collections import Counter
import jsonpickle
import shapely
from shapely.geometry import LineString
import carla
import scenic
from scenic.core.vectors import Vector
from scenic.domains.driving.roads import Network
from scenic.core.regions import PolylineRegion

# This project
from src.scenariogen.core.geometry import CurvilinearTransform
from scenariogen.core.fuzz_input import FuzzInput, Spline
import scenariogen.simulators.carla.visualization as visualization

# Connect to the Carla simulator
client = carla.Client('127.0.0.1', 2000)
world = client.get_world()

settings = world.get_settings()
settings.synchronous_mode = False
world.apply_settings(settings)

# Load a seed, plot its trajectory
with open('experiments/seeds/0.json', 'r') as f:
    seed = jsonpickle.decode(f.read())
    assert isinstance(seed, FuzzInput)

resolution = 0.05
umin, umax = 0, seed.timings[0].ctrlpts[-1][1]
footprint, timing, route = seed.footprints[0], seed.timings[0], seed.routes[0]
axis = LineString((p for uid in route for p in network.elements[uid].centerline.lineString.coords))
transform = CurvilinearTransform(axis)
footprint_rectilinear = Spline(degree=footprint.degree,
                              ctrlpts=(transform.rectilinear(p) for p in footprint.ctrlpts),
                              knotvector=footprint.knotvector)
visualization.draw_spline(world, footprint, timing, resolution, umin, umax,
                          size=0.1,
                          color=carla.Color(0, 0, 255),
                          draw_ctrlpts=True,
                          lifetime=600)

network = Network.fromFile(seed.config['map'])
route = seed.routes[0]
lanes = [network.elements[lane_id]
          for lane_id in route]
ps = lanes[0].centerline.points
ps_simple = [ps[0], ps[1]]
v0 = Vector(*ps_simple[-1]) - Vector(*ps_simple[-2])
for i in range(2, len(ps)):
    v1 = Vector(*ps[i]) - Vector(*ps_simple[-1])
    if v0.dot(v1) >= 0:
        ps_simple.append(ps[i])
        v0 = v1

polyline=PolylineRegion(ps_simple)
p = footprint.ctrlpts[5]
# Curvilinear calculations
v = Vector(p[0], p[1])
y = polyline.signedDistanceTo(v)
proj = polyline.project(v)
p_mirror = v + (Vector(proj.x, proj.y) - v)*2
splitter = shapely.geometry.LineString([p, p_mirror.coordinates])
visualization.draw_point(world, p_mirror, .2,
                            size=0.1,
                            color=carla.Color(255, 0, 0),
                            lifetime=300)
# result = shapely.ops.split(polyline.lineString, splitter)
# poly_parts = result.geoms
poly_parts = polyline.lineString.difference(splitter).geoms
print(len(poly_parts))
for p in poly_parts[0].coords:
    visualization.draw_point(world, p, .1,
                            size=0.2,
                            color=carla.Color(0, 255, 0),
                            lifetime=300)
