import scenariogen.simulators.carla.visualization as visualization

scenario ShowIntersectionScenario(intersection):
  setup:  
    monitor ShowIntersectionMonitor:
      carla_world = simulation().world
      visualization.draw_intersection(carla_world, intersection, draw_lanes=True)
      visualization.set_camera(carla_world, intersection, height=50)
      wait