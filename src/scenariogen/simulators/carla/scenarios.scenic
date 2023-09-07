import carla
import queue
import scenariogen.simulators.carla.visualization as visualization
from scenariogen.core.errors import EgoCollisionError

scenario ShowIntersectionScenario(intersection):
  setup:  
    monitor ShowIntersectionMonitor:
      carla_world = simulation().world
      visualization.draw_intersection(carla_world, intersection, draw_lanes=False)
      visualization.set_camera(carla_world, intersection, height=70)
      wait

scenario RaiseEgoCollisionScenario(config):
  setup:
    def on_collision(event, q):
      q.put(event.other_actor.id)
     
    monitor collisions:
      id_queue = queue.Queue()
      agents = simulation().agents
      id2name = {agent.carlaActor.id:agent.name for agent in agents}
      carla_world = simulation().world
      ego_carla_actor = next(x for x in agents if x.name == 'ego').carlaActor
      bp = carla_world.get_blueprint_library().find('sensor.other.collision')
      sensor = carla_world.spawn_actor(bp, carla.Transform(), attach_to=ego_carla_actor)
      sensor.listen(lambda e: on_collision(e, id_queue))
      while (simulation().currentTime < config['steps']) and id_queue.empty():
        wait
      sensor.destroy()
      if not id_queue.empty():
        agent_id = id_queue.get()
        raise EgoCollisionError(id2name[agent_id])
      
