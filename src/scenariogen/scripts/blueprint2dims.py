#!/usr/bin/env python3.8

import carla
import jsonpickle

client = carla.Client('127.0.0.1', 2000)
world = client.get_world()
spawn_points = world.get_map().get_spawn_points()
blueprint_library = world.get_blueprint_library()
blueprints_cars = [v for v in blueprint_library.filter('vehicle.*.*')
                   if v.get_attribute('number_of_wheels').as_int() == 4]
blueprint2dims = {}

for bp, sp in zip(blueprints_cars, spawn_points):
  actor = world.try_spawn_actor(bp, sp)
  if not actor:
      continue
  blueprint2dims[bp.id] = {'length': actor.bounding_box.extent.x * 2,
                           'width': actor.bounding_box.extent.y * 2,
                          }
  actor.destroy()

blueprint2dims = dict(sorted(blueprint2dims.items(), key=lambda item: item[1]['length']))

with open('src/scenariogen/simulators/carla/blueprint2dims_cars.json', 'w') as f:
  corpus_json = jsonpickle.encode(blueprint2dims, indent=1)
  f.write(corpus_json)


