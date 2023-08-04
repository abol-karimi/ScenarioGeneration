from scenic.simulators.carla.simulator import CarlaSimulation
import scenariogen.simulators.carla.visualization as visualization

scenario ShowIntersection():
  setup:  
    monitor show_intersection():
      if isinstance(simulation(), CarlaSimulation):
        carla_world = simulation().world
        visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
        visualization.set_camera(carla_world, intersection, height=50)
      wait