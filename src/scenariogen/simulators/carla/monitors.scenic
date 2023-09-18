param carla_map = 'Town05'
carla_map = globalParameters.carla_map
param map = f'/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{carla_map}.xodr'
model scenic.simulators.carla.model

import carla
import queue
import scenariogen.simulators.carla.visualization as visualization
from scenariogen.core.errors import EgoCollisionError

monitor ShowIntersectionMonitor(intersection_uid, show_lanes=False, label_lanes=False, show_carla_axes=False):
  intersection = network.elements[intersection_uid]
  carla_world = simulation().world
  visualization.draw_intersection(carla_world,
                                  intersection, 
                                  draw_lanes=show_lanes,
                                  label_lanes=label_lanes, 
                                  draw_carla_axes=show_carla_axes)
  visualization.set_camera(carla_world, intersection, height=90)
  wait

monitor LabelCarsMonitor():
  agents = simulation().agents
  while True:
    for agent in agents:
      visualization.label_car(simulation().world, agent)
    wait

def on_collision(event, q):
  q.put(event)
  
monitor RaiseEgoCollisionMonitor(config):
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
    sensor.destroy()
    if not event_queue.empty():
      raise EgoCollisionError(event_queue.get().other_actor)
  else:
    wait
