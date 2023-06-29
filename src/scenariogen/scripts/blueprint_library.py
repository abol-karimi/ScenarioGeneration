#!/usr/bin/env python3.8

import carla
import jsonpickle

client = carla.Client('127.0.0.1', 2000)
world = client.get_world()
spawn_points = world.get_map().get_spawn_points()
blueprint_library = world.get_blueprint_library()
vehicle_blueprints = [v for v in blueprint_library.filter('*')]
bp_properties = {}

for bp, sp in zip(vehicle_blueprints, spawn_points):
    actor = world.try_spawn_actor(bp, sp)
    if not actor:
       continue
    bp_properties[bp.id] = {'width': actor.bounding_box.extent.y * 2,
                            'length': actor.bounding_box.extent.x * 2}
    print(bp.id, bp_properties[bp.id])
    actor.destroy()

with open('src/scenariogen/simulators/carla/blueprint_library_all.json', 'w') as f:
  corpus_json = jsonpickle.encode(bp_properties, indent=1)
  f.write(corpus_json)


