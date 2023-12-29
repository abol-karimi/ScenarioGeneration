param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.carla.model

import carla
import queue
import scenariogen.simulators.carla.visualization as visualization
from scenariogen.core.errors import EgoCollisionError, NonegoCollisionError

monitor ShowIntersectionMonitor(intersection_uid,
                                show_lanes=False,
                                label_lanes=False,
                                show_carla_axes=False,
                                life_time=-1
                                ):
  intersection = network.elements[intersection_uid]
  carla_world = simulation().world
  visualization.draw_intersection(carla_world,
                                  intersection, 
                                  draw_lanes=show_lanes,
                                  label_lanes=label_lanes, 
                                  draw_carla_axes=show_carla_axes,
                                  life_time=life_time)
  visualization.set_camera(carla_world, intersection, height=100)
  wait

monitor LabelCarsMonitor():
  agents = simulation().agents
  while True:
    for agent in agents:
      visualization.label_car(simulation().world, agent)
    wait

def on_collision(event, q):
  q.put(event)
  
monitor ForbidEgoCollisionsMonitor(config):
  agents = simulation().agents
  names = {agent.name for agent in agents}
  if 'ego' in names:
    ego_carla_actor = next(x for x in agents if x.name == 'ego').carlaActor
    event_queue = queue.Queue()
    carla_world = simulation().world
    bp = carla_world.get_blueprint_library().find('sensor.other.collision')
    sensor = carla_world.spawn_actor(bp, carla.Transform(), attach_to=ego_carla_actor)
    sensor.listen(lambda e: on_collision(e, event_queue))
    while (simulation().currentTime < config['steps']) and event_queue.empty():
      wait
    if sensor.is_listening():
      sensor.stop()
    sensor.destroy()
    print('Ego collision sensor destroyed.')
    if not event_queue.empty():
      raise EgoCollisionError(event_queue.get().other_actor)
  else:
    wait

monitor ForbidNonegoCollisionsMonitor(config):
  event_queue = queue.Queue()
  carla_world = simulation().world
  bp = carla_world.get_blueprint_library().find('sensor.other.collision')
  sensors = []
  for agent in simulation().agents:
    if agent.name == 'ego':
      continue
    sensor = carla_world.spawn_actor(bp, carla.Transform(), attach_to=agent.carlaActor)
    sensors.append(sensor)
    sensor.listen(lambda e: on_collision(e, event_queue))

  while (simulation().currentTime < config['steps']) and event_queue.empty():
    wait
  
  for sensor in sensors:
    if sensor.is_listening():
      sensor.stop()
    sensor.destroy()
  print('All nonego collision sensors destroyed.')

  if not event_queue.empty():
    event = event_queue.get()
    print(f'{event.actor} collided with {event.other_actor} with impulse {event.normal_impulse.length()}.')
    require False
  else:
    wait